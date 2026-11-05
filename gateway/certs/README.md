# Supabase public CA

Downloaded over HTTPS from Supabase's official certificate location:
https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt

The URL is defined by `ssl:certificate_url` in Supabase's Studio source:
https://github.com/supabase/supabase/blob/master/apps/studio/hooks/custom-content/custom-content.json

Observed 2026-11-02. SHA-256 certificate fingerprint:
`80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA`

This is a public trust anchor, not a private credential. Use with hostname and certificate verification enabled. Revalidate provenance before rotating it. Do not replace it with an arbitrary certificate copied from an unverified database connection.
