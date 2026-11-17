# Evaluation Results for warm_lr_50_50

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.34% (9934 / 10000)
	- **Wrong predictions:** 66

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 97.71% (39083 / 40000)
	- **Wrong predictions:** 917

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 96.33% (14242 / 14785)
	- **Wrong predictions:** 543

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.68% (51510 / 52197)
	- **Wrong predictions:** 687

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 89.54% (11730 / 13100)
	- **Wrong predictions:** 1370

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.83% (2349 / 2353)
	- **Wrong predictions:** 4

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.34% (3797 / 3861)
	- **Wrong predictions:** 64

### Performance

- **Accuracy:** 97.32%
- **Precision:** 95.82%
- **Recall:** 95.07%
- **F1 Score:** 95.45%

### Confusion Matrix

- **True Positives:** 38255
- **True Negatives:** 94390
- **False Positives:** 1668
- **False Negatives:** 1983

### Totals
- **Correct:** 132645
- **Wrong:** 3651
- **Total:** 136296
