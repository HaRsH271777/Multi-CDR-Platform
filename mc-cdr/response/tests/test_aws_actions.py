import boto3
from moto import mock_aws

from response.actions.aws_actions import AWSActions


@mock_aws
def test_revoke_iam_sessions_no_login_profile_returns_success_no_profile():
    boto3.setup_default_session(region_name="us-east-1")
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")

    actions = AWSActions()
    result = actions.revoke_iam_sessions("alice")

    assert result == "success_no_profile"


@mock_aws
def test_revoke_iam_sessions_with_login_profile_returns_success():
    boto3.setup_default_session(region_name="us-east-1")
    iam = boto3.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Temp1234!")

    actions = AWSActions()
    result = actions.revoke_iam_sessions("bob")

    assert result == "success"


@mock_aws
def test_revert_bucket_acl_returns_success():
    boto3.setup_default_session(region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="mc-cdr-test-bucket")

    actions = AWSActions()
    result = actions.revert_bucket_acl("mc-cdr-test-bucket")

    assert result == "success"
