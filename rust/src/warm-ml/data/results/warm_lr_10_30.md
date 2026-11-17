# Evaluation Results for warm_lr_10_30

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.50% (9950 / 10000)
	- **Wrong predictions:** 50

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 85.08% (34032 / 40000)
	- **Wrong predictions:** 5968

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 98.92% (14625 / 14785)
	- **Wrong predictions:** 160

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.39% (51356 / 52197)
	- **Wrong predictions:** 841

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 95.35% (12491 / 13100)
	- **Wrong predictions:** 609

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.79% (2348 / 2353)
	- **Wrong predictions:** 5

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.34% (3797 / 3861)
	- **Wrong predictions:** 64

### Performance

- **Accuracy:** 94.35%
- **Precision:** 85.15%
- **Recall:** 97.95%
- **F1 Score:** 91.10%

### Confusion Matrix

- **True Positives:** 39414
- **True Negatives:** 89185
- **False Positives:** 6873
- **False Negatives:** 824

### Totals
- **Correct:** 128599
- **Wrong:** 7697
- **Total:** 136296
