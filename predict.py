# PREDICT.PY
import pickle
from detection_engine import predict_url

with open(
    "models/rf_qr_model.pkl",
    "rb"
) as f:
    model = pickle.load(f)

print("==================================")
print("QR URL THREAT DETECTION")
print("Random Forest Loaded")
print("==================================")

while True:
    url = input("\nEnter URL (q to quit): ").strip()

    if url.lower() == "q":
        break

    try:
        result = predict_url(model, url)

        print("\n==================================")
        print("PREDICTION RESULT")
        print("==================================")
        print(f"URL: {result['url']}")
        print(f"ML Result: {result['ml_result']}")
        print(f"Confidence: {result['confidence']:.2f}%")
        print(f"HTTPS: {result['https']}")
        print(f"DNS: {result['dns']}")
        print(f"Final Status: {result['final_status']}")

        print("\n==================================")
        print("FEATURES")
        print("==================================")
        for key, value in result['feature_info'].items():
            print(f"{key}: {value}")

        if result['suspicious_reasons']:
            print("\nSuspicious Indicators Found:")
            for reason in result['suspicious_reasons']:
                print(f"- {reason}")
    except Exception as e:
        print("\nError:", str(e))
