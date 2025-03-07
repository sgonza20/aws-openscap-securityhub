import json
import boto3
import datetime
import os
import xml.etree.ElementTree as ET
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session

s3 = boto3.client('s3')
cloudWatch = boto3.client('cloudwatch')
dynamodb = boto3.resource('dynamodb')
securityHub = boto3.client('securityhub')
ssmClient = boto3.client('ssm')

# OpenSearch Endpoint (set as an environment variable)
OPENSEARCH_ENDPOINT = os.environ.get('OPENSEARCH_ENDPOINT')
REGION = os.environ.get('AWS_REGION', 'us-east-1')

def lambda_handler(event, context):
    bucket_name = "testingcftmarch2024"
    file_key = "scap-results.xml"
    aws_account_id = "344594102751"
    region = "us-east-1"

    instanceId = file_key.split('/')[0]

    obj = s3.get_object(Bucket=bucket_name, Key=file_key)

    useSecurityHub = ssmClient.get_parameter(Name='/SCAPTesting/EnableSecurityHub')['Parameter']['Value']

    root = ET.fromstring(obj['Body'].read())

    testResult = root.find(".//{http://checklists.nist.gov/xccdf/1.2}TestResult")
    testVersion = testResult.attrib.get("version")

    high = 0
    medium = 0
    low = 0
    unknown = 0

    ignoreList = getIgnoreList()
    
    dynamoDbItems = []
    securityHubFindings = []

    for item in testResult:
        testId = str(item.attrib.get("idref"))
        if '.' in testId:
            testId = testId[testId.rindex('.') + 1:]

        if testId not in ignoreList and item.findtext('{http://checklists.nist.gov/xccdf/1.2}result') == "fail":
            saveToDynamoDB(dynamoDbItems, instanceId, item, bucket_name, file_key)
            pushToSecurityHub(securityHubFindings, root, instanceId, item, region, aws_account_id, testVersion, bucket_name, file_key)

            # Send result to OpenSearch
            send_to_opensearch(instanceId, testId, item.attrib.get("severity"), item.findtext('{http://checklists.nist.gov/xccdf/1.2}result'), testVersion)

            if item.attrib.get("severity") == "high":
                high += 1
            elif item.attrib.get("severity") == "medium":
                medium += 1
            elif item.attrib.get("severity") == "low":
                low += 1
            elif item.attrib.get("severity") == "unknown":
                unknown += 1

    sendMetric(high, 'SCAP High Finding', instanceId)
    sendMetric(medium, 'SCAP Medium Finding', instanceId)
    sendMetric(low, 'SCAP Low Finding', instanceId)

    table = dynamodb.Table('SCAP_Scan_Results')
    with table.batch_writer() as batch:
        for item in dynamoDbItems:
            batch.put_item(Item=item)

    if useSecurityHub == "true":
        try:
            batch_send_securityhub_findings(securityHubFindings)
        except Exception as e:
            print("SecurityHub error: " + str(e))

def sign_request(method, endpoint, body):
    session = Session()
    credentials = session.get_credentials()
    request = AWSRequest(method=method, url=endpoint, data=json.dumps(body), headers={"Content-Type": "application/json"})
    SigV4Auth(credentials, "aoss", REGION).add_auth(request)
    return request

def send_to_opensearch(instance_id, rule_name, severity, status, timestamp):
    if not OPENSEARCH_ENDPOINT:
        print("OpenSearch endpoint is not set.")
        return

    index_name = "scap-results"
    doc_id = f"{instance_id}-{rule_name}"
    url = f"{OPENSEARCH_ENDPOINT}/{index_name}/_doc/{doc_id}"

    data = {
        "InstanceId": instance_id,
        "SCAP_Rule_Name": rule_name,
        "Severity": severity,
        "Status": status,
        "Timestamp": timestamp
    }

    # Sign the request
    signed_request = sign_request("PUT", url, data)

    # Execute request using boto3's low-level client
    client = boto3.client("opensearchserverless")
    response = client.make_request(
        method=signed_request.method,
        url=signed_request.url,
        headers=dict(signed_request.headers),
        data=signed_request.body
    )

    print(f"OpenSearch response for {rule_name}: {response}")


def batch_send_securityhub_findings(findings):
    batch_size = 100
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        result = securityHub.batch_import_findings(Findings=batch)
        print("SecurityHub batch result:", result)


def saveToDynamoDB(dynamoDbItems, instanceId, item, bucket_name, file_key):
    dynamoDbItems.append({
        'InstanceId': instanceId,
        'SCAP_Rule_Name': item.attrib.get("idref"),
        'time': item.attrib.get("time"),
        'severity': item.attrib.get("severity"),
        'result': item.findtext('{http://checklists.nist.gov/xccdf/1.2}result'),
        'report_url': 's3://' + bucket_name + "/" + file_key.replace('.xml', '.html')
    })


def sendMetric(value, title, instanceId):
    cloudWatch.put_metric_data(
        Namespace='Compliance',
        MetricData=[
            {
                'MetricName': title,
                'Dimensions': [
                    {
                        'Name': 'InstanceId',
                        'Value': instanceId
                    },
                ],
                'Value': value
            }
        ]
    )


def getIgnoreList():
    table = dynamodb.Table('SCAP_Scan_Ignore_List')
    response = table.scan()
    return [item['SCAP_Rule_Name'] for item in response['Items']]


def pushToSecurityHub(securityHubFindings, root, instanceId, item, region, aws_account_id, testVersion, bucket_name, file_key):
    rule = root.find(".//{http://checklists.nist.gov/xccdf/1.2}Rule[@id='" + item.attrib.get("idref") + "']")
    profile = root.find('.//{http://checklists.nist.gov/xccdf/1.2}Profile[@id="xccdf_org.ssgproject.content_profile_stig"]')

    time = item.attrib.get("time")
    if time.find('+') != -1:
        time = time[:time.rindex('+')]
    time += ".000Z"

    securityHubFindings.append({
        'SchemaVersion': '2018-10-08',
        'Id': item.attrib.get("idref") + "_" + file_key,
        'ProductArn': f'arn:aws:securityhub:{region}:{aws_account_id}:product/{aws_account_id}/default',
        'GeneratorId': 'OpenSCAP ' + item.attrib.get("idref"),
        'AwsAccountId': aws_account_id,
        'Types': ['Software and Configuration Checks'],
        'FirstObservedAt': time,
        'LastObservedAt': time,
        'CreatedAt': time,
        'UpdatedAt': time,
        'Severity': {'Label': item.attrib.get("severity").upper()},
        'Title': rule.findtext('{http://checklists.nist.gov/xccdf/1.2}title'),
        'Description': str(rule.findtext('{http://checklists.nist.gov/xccdf/1.2}description')) + " ",
        'Remediation': {
            'Recommendation': {
                'Text': 'For remediation please see: s3://' + bucket_name + '/' + file_key.replace('.xml', '.html')
            }
        },
        'ProductFields': {
            "ProviderName": str(rule.findtext('{http://checklists.nist.gov/xccdf/1.2}title')) + " ",
            "ProviderVersion": testVersion
        },
        'Resources': [
            {
                'Type': 'AwsEc2Instance',
                'Id': instanceId,
                'Region': region
            },
        ],
        'Compliance': {'Status': 'FAILED'},
        'WorkflowState': 'NEW',
        'Workflow': {'Status': 'NEW'}
    })
