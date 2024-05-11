from flask import Flask, abort, jsonify, request, render_template
from flask_cors import CORS, cross_origin
import time
import json
import datetime
import os
from flask_restful import Resource, Api
import joblib
import index
import numpy as np
import joblib
#import inputScript
from index import *
#load the pickle file
classifier = joblib.load('final_models/rf_final.pkl')
import numpy as np
import re
#Use of IP or not in domain


application = app = Flask(__name__)

@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/getprediction", methods=['POST'])
def getprediction():
    
    #load the pickle file
    classifier = joblib.load('final_models/rf_final.pkl')

    #checking and predicting    
    input = [x for x in request.form.values()]
    for url in input:
       x=get_prediction_from_url(url)
    return render_template('index.html', output='The url is of type :{}'.format(x))
    
if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))
