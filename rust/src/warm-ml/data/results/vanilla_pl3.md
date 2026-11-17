# Evaluation Results for vanilla_pl3

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.88% (9988 / 10000)
	- **Wrong predictions:** 12

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 27.09% (10836 / 40000)
	- **Wrong predictions:** 29164

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.61% (14728 / 14785)
	- **Wrong predictions:** 57

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 30.43% (15885 / 52197)
	- **Wrong predictions:** 36312

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 93.20% (12209 / 13100)
	- **Wrong predictions:** 891

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.62% (2344 / 2353)
	- **Wrong predictions:** 9

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 95.39% (3683 / 3861)
	- **Wrong predictions:** 178

### Performance

- **Accuracy:** 51.12%
- **Precision:** 37.43%
- **Recall:** 97.59%
- **F1 Score:** 54.10%

### Confusion Matrix

- **True Positives:** 39269
- **True Negatives:** 30404
- **False Positives:** 65654
- **False Negatives:** 969

### Totals
- **Correct:** 69673
- **Wrong:** 66623
- **Total:** 136296
