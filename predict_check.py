import pickle
from predict import extract_features

model = pickle.load(open('models/rf_qr_model.pkl','rb'))
features, info = extract_features('https://google.com')
print('Classes:', model.classes_)
print('Prediction:', model.predict(features)[0])
print('Probability:', model.predict_proba(features)[0])
print('Feature info:', info)
