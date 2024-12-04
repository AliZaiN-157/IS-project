import joblib
import numpy as np


with open('./Model/Try/lgb_model.pkl', 'rb') as file:
    model = joblib.load(file)


def predict_url(url: str):

    url_features = {
        'Querylength': len(url),
        'domain_token_count': url.count('.'),
        'path_token_count': url.count('/'),
        'avgdomaintokenlen': np.mean([len(t) for t in url.split('.') if t]),
        'longdomaintokenlen': max([len(t) for t in url.split('.') if t]),
        'avgpathtokenlen': np.mean([len(t) for t in url.split('/') if t]),
    }
    prediction = np.array([list(url_features.values())])

    xgb_pred = model.predict(prediction)
    categories = ['defacement', 'benign', 'phishing', 'malware', 'spam']
    return categories[int(xgb_pred[0])]
