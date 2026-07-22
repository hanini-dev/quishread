# QUISHREAD

QUISHREAD is a Python-based QR code security detection system that identifies malicious URLs embedded in QR codes using the Random Forest machine learning algorithm.

## Features

- Scan and extract URLs from QR codes
- Detect phishing and malicious URLs
- Random Forest-based classification
- Offline prediction support
- Model retraining with custom datasets
- Export training datasets

## Technologies

- Python
- Flask
- Scikit-learn
- Random Forest
- Firebase
- Pandas
- NumPy

## Dataset

This project uses publicly available phishing URL datasets, including:

- PhiUSIIL Dataset
- LegitPhish Dataset

## Project Structure

```
quishread/
├── app.py
├── train.py
├── detection_engine.py
├── predict.py
├── requirements.txt
├── datasets/
├── models/
└── results/
```

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

## Disclaimer

This project was developed for educational and research purposes as part of a Final Year Project (FYP).
