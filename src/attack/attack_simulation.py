from src.attack.experiment_engine import run_forgery_suite

def run_partial_attack():
    print("--- Running MD5 Attack Suite (25 tests) ---")
    md5_summary = run_forgery_suite(mode="MD5", total_tests=25)

    print(f"Total tests:            {md5_summary.total_tests}")
    print(f"Successful forgeries:   {md5_summary.successful_forgeries}")
    print(f"Attack success rate:    {md5_summary.success_rate:.1f}%")
    print(f"Integrity after attack: {md5_summary.integrity_rate:.1f}%")

    if md5_summary.success_rate >= 90:
        print("Result: Requirement satisfied (>= 90% forgery success before prevention).")
    else:
        print("Result: Requirement NOT satisfied (< 90% forgery success).")

    print("\n--- Running SHA-256 Prevention Suite (25 tests) ---")
    sha_summary = run_forgery_suite(mode="SHA-256", total_tests=25)

    print(f"Total tests:            {sha_summary.total_tests}")
    print(f"Successful forgeries:   {sha_summary.successful_forgeries}")
    print(f"Attack success rate:    {sha_summary.success_rate:.1f}%")
    print(f"Integrity after fix:    {sha_summary.integrity_rate:.1f}%")

    if sha_summary.success_rate == 0:
        print("Result: Prevention satisfied (0% forgery success after SHA-256).")
    else:
        print("Result: Prevention NOT satisfied (non-zero forgery success).")

if __name__ == "__main__":
    run_partial_attack()