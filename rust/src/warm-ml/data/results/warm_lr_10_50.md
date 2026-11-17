# Evaluation Results for warm_lr_10_50

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.31% (9931 / 10000)
	- **Wrong predictions:** 69

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 88.44% (35375 / 40000)
	- **Wrong predictions:** 4625

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 95.46% (14114 / 14785)
	- **Wrong predictions:** 671

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.85% (51595 / 52197)
	- **Wrong predictions:** 602

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 95.01% (12446 / 13100)
	- **Wrong predictions:** 654

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.75% (2347 / 2353)
	- **Wrong predictions:** 6

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.34% (3797 / 3861)
	- **Wrong predictions:** 64

### Performance

- **Accuracy:** 95.09%
- **Precision:** 88.01%
- **Recall:** 96.52%
- **F1 Score:** 92.07%

### Confusion Matrix

- **True Positives:** 38838
- **True Negatives:** 90767
- **False Positives:** 5291
- **False Negatives:** 1400

### Totals
- **Correct:** 129605
- **Wrong:** 6691
- **Total:** 136296
