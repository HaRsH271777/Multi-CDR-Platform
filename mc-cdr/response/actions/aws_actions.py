from __future__ import annotations

import logging
import time

import boto3

logger = logging.getLogger(__name__)


class AWSActions:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    @staticmethod
    def _duration_ms(start: float) -> int:
        return int((time.perf_counter() - start) * 1000)

    def revoke_iam_sessions(self, principal_id: str) -> str:
        iam = boto3.client("iam")
        start = time.perf_counter()
        try:
            if self.dry_run:
                duration = self._duration_ms(start)
                logger.info(
                    "Dry-run revoke_iam_sessions for %s in %d ms",
                    principal_id,
                    duration,
                )
                return "stub_executed"

            iam.delete_login_profile(UserName=principal_id)
            duration = self._duration_ms(start)
            logger.info(
                "Revoked login profile for %s in %d ms", principal_id, duration
            )
            return "success"
        except iam.exceptions.NoSuchEntityException:
            duration = self._duration_ms(start)
            logger.warning(
                "No login profile found for %s in %d ms", principal_id, duration
            )
            return "success_no_profile"
        except Exception as exc:
            duration = self._duration_ms(start)
            logger.error(
                "Failed to revoke login profile for %s in %d ms: %s",
                principal_id,
                duration,
                exc,
            )
            return f"failed: {exc}"

    def remove_sg_rule(self, sg_id: str, ip_permission: dict) -> str:
        ec2 = boto3.client("ec2")
        start = time.perf_counter()
        try:
            if self.dry_run:
                duration = self._duration_ms(start)
                logger.info(
                    "Dry-run remove_sg_rule for %s in %d ms", sg_id, duration
                )
                return "stub_executed"

            ec2.revoke_security_group_ingress(
                GroupId=sg_id, IpPermissions=[ip_permission]
            )
            duration = self._duration_ms(start)
            logger.info("Removed SG rule for %s in %d ms", sg_id, duration)
            return "success"
        except Exception as exc:
            duration = self._duration_ms(start)
            logger.error(
                "Failed to remove SG rule for %s in %d ms: %s",
                sg_id,
                duration,
                exc,
            )
            return f"failed: {exc}"

    def revert_bucket_acl(self, bucket_name: str) -> str:
        s3 = boto3.client("s3")
        start = time.perf_counter()
        try:
            if self.dry_run:
                duration = self._duration_ms(start)
                logger.info(
                    "Dry-run revert_bucket_acl for %s in %d ms",
                    bucket_name,
                    duration,
                )
                return "stub_executed"

            s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
            duration = self._duration_ms(start)
            logger.info("Reverted ACL for %s in %d ms", bucket_name, duration)
            return "success"
        except Exception as exc:
            duration = self._duration_ms(start)
            logger.error(
                "Failed to revert ACL for %s in %d ms: %s",
                bucket_name,
                duration,
                exc,
            )
            return f"failed: {exc}"
