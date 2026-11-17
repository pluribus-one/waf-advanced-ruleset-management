# Evaluation Results for vanilla_pl1

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 93.33% (9333 / 10000)
	- **Wrong predictions:** 667

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 97.13% (38853 / 40000)
	- **Wrong predictions:** 1147

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 88.06% (13019 / 14785)
	- **Wrong predictions:** 1766

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 79.65% (41577 / 52197)
	- **Wrong predictions:** 10620

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 68.25% (8941 / 13100)
	- **Wrong predictions:** 4159

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 98.73% (2323 / 2353)
	- **Wrong predictions:** 30

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 100.00% (3861 / 3861)
	- **Wrong predictions:** 0

### Performance

- **Accuracy:** 86.51%
- **Precision:** 74.07%
- **Recall:** 83.54%
- **F1 Score:** 78.52%

### Confusion Matrix

- **True Positives:** 33616
- **True Negatives:** 84291
- **False Positives:** 11767
- **False Negatives:** 6622

### Totals
- **Correct:** 117907
- **Wrong:** 18389
- **Total:** 136296
