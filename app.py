from flask import Flask,render_template,url_for,request
from flask_bootstrap import Bootstrap 
import pandas as pd 
import numpy as np 
import InputScript
# ML Packages
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.externals import joblib


app = Flask(__name__)
Bootstrap(app)


@app.route('/')
def index():
	return render_template('index.html')

def get_prediction_from_url(test_url):
	TestCase = InputScript.main(test_url)
	TestCase = np.array(TestCase).reshape(1,-1) 
	ytb1 = open("finalized_model.pkl","rb")
	clf1 = joblib.load(ytb1)
	return clf1.predict(TestCase)

@app.route('/predict', methods=['POST'])
def predict():
	ytb_model = open("finalized_model.pkl","rb")
	clf = joblib.load(ytb_model)


	# Receives the input query from form\
	if request.method == 'POST':
		comment = request.form['comment']
		data = str(comment)
		pred = get_prediction_from_url(data)




		


		#vect = cv.transform(data).toarray()
		#my_prediction = clf.predict(vect)
		
	return render_template('results.html',prediction = pred)

    #return render_template('results.html',prediction = my_prediction,name = namequery.upper())


if __name__ == '__main__':
	app.run(debug=True)