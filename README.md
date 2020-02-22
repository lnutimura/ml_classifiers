# ml_classifiers
**ml_classifiers** is a Snort 3 Machine Learning-based Inspector for Network Traffic Bi-directional Flow Classification.

It employs several machine learning models previously trained on [**CICIDS2017**](https://www.unb.ca/cic/datasets/ids-2017.html) to classify bi-directional flows in real time, completely replacing the Snort 3's default signature-based (or rule-based) detection approach.

**Trained classifiers:**
* Gaussian/Bernoulli Naive Bayes;
* Linear Support Vector Machine;
* Decision Tree;
* Random Forest;
* AdaBoost.

This project was developed for research purposes of my master's thesis.
