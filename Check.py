import joblib
import InputScript
import sys
import numpy as np



def get_prediction_from_url(test_url):
    
    TestCase = InputScript.main(test_url)
    
    TestCase = np.array(TestCase).reshape((1, -1))

    PickleRF = joblib.load('/finalized_model.pkl')

    Pred = PickleRF.predict(TestCase)
    
    return Pred


def main(url):
    
    pred = get_prediction_from_url(url)

    if int(pred[0]) == 1:
        print("SAFE")
    elif int(pred[0]) == -1:
        print("PHISHING")

if __name__ == "__main__":
    url = input()
    main(url)
    
