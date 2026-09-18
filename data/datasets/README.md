# Vendor benchmark dataset

This directory stores synthetic multi-vendor configuration samples used for benchmarking NetSecureAI across supported network device families.

## Generated dataset

The generator script at `backend/scripts/generate_vendor_dataset.py` creates a benchmark corpus for the following vendors:

- Cisco
- Juniper
- Fortinet
- Palo Alto
- Arista
- HPE Aruba
- Huawei
- Check Point
- SONiC

Each vendor includes secure, insecure, and mixed state variants to support testing across multiple frameworks:

- CIS Benchmarks
- NIST SP 800-53
- DISA STIG
- ISO/IEC 27001

## Notes

This dataset is intentionally deterministic and offline-safe. It is designed as a benchmark pack for local validation and can be extended with public vendor samples when needed for real-world collection.
