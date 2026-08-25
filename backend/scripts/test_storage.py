"""Storage connectivity test script.

Run from the project root or backend folder. It will attempt to:
- connect to Postgres if DATABASE_URL is set
- perform a HeadBucket/list or put test to S3 if S3_BUCKET is set

This script is safe and performs non-destructive checks.
"""
import os
import sys

DATABASE_URL = os.getenv('DATABASE_URL')
S3_BUCKET = os.getenv('S3_BUCKET')
S3_ENDPOINT = os.getenv('S3_ENDPOINT')

print('DATABASE_URL=', DATABASE_URL)
print('S3_BUCKET=', S3_BUCKET)

if DATABASE_URL:
    try:
        import psycopg2
        print('psycopg2 available')
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.close()
            print('Postgres: connection OK')
        except Exception as e:
            print('Postgres connection failed:', e)
    except Exception:
        print('psycopg2 is not installed; cannot test Postgres connectivity')
else:
    print('No DATABASE_URL set; skipping Postgres test')

if S3_BUCKET:
    try:
        import boto3
        s3 = boto3.client('s3', endpoint_url=S3_ENDPOINT) if S3_ENDPOINT else boto3.client('s3')
        try:
            # Attempt to list objects (requires permissions)
            resp = s3.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
            print('S3: list_objects_v2 succeeded (or bucket exists and is accessible)')
        except Exception as e:
            print('S3 list failed:', e)
    except Exception:
        print('boto3 is not installed; cannot test S3 connectivity')
else:
    print('No S3_BUCKET set; skipping S3 test')

print('\nDone')
