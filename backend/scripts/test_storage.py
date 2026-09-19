"""Storage connectivity test script.

Run from the project root or backend folder. It will attempt to:
- connect to Postgres if DATABASE_URL is set
- perform a HeadBucket/list or put test to S3 if S3_BUCKET is set

This script is safe and performs non-destructive checks.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')

DATABASE_URL = os.getenv('DATABASE_URL')
S3_BUCKET = os.getenv('S3_BUCKET')
S3_ENDPOINT = os.getenv('S3_ENDPOINT')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_BUCKET = os.getenv('SUPABASE_BUCKET', 'configurations')

print('DATABASE_URL configured:', bool(DATABASE_URL))
print('S3_BUCKET configured:', bool(S3_BUCKET))

if SUPABASE_URL and os.getenv('SUPABASE_SECRET_KEY'):
    try:
        from supabase import create_client

        client = create_client(SUPABASE_URL, os.getenv('SUPABASE_SECRET_KEY'))
        print('Supabase URL configured:', True)
        for table in ('analyses', 'mappings', 'audit_events'):
            try:
                rows = client.table(table).select('*').limit(1).execute().data or []
                print(f'Supabase table {table}: OK ({len(rows)} sample rows)')
            except Exception as exc:
                print(f'Supabase table {table}: unavailable ({type(exc).__name__})')
        try:
            client.storage.from_(SUPABASE_BUCKET).list(path='', options={'limit': 1})
            print(f'Supabase bucket {SUPABASE_BUCKET}: OK')
        except Exception as exc:
            print(f'Supabase bucket {SUPABASE_BUCKET}: unavailable ({type(exc).__name__})')
    except Exception as exc:
        print(f'Supabase client unavailable ({type(exc).__name__})')
else:
    print('Supabase credentials not configured; skipping Supabase test')

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
