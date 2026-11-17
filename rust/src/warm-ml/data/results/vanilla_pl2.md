# Evaluation Results for vanilla_pl2

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.66% (9966 / 10000)
	- **Wrong predictions:** 34

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 60.30% (24120 / 40000)
	- **Wrong predictions:** 15880

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 93.31% (13796 / 14785)
	- **Wrong predictions:** 989

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 37.99% (19830 / 52197)
	- **Wrong predictions:** 32367

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 84.30% (11043 / 13100)
	- **Wrong predictions:** 2057

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.07% (2331 / 2353)
	- **Wrong predictions:** 22

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 95.39% (3683 / 3861)
	- **Wrong predictions:** 178

### Performance

- **Accuracy:** 62.19%
- **Precision:** 43.40%
- **Recall:** 92.29%
- **F1 Score:** 59.04%

### Confusion Matrix

- **True Positives:** 37136
- **True Negatives:** 47633
- **False Positives:** 48425
- **False Negatives:** 3102

### Totals
- **Correct:** 84769
- **Wrong:** 51527
- **Total:** 136296
