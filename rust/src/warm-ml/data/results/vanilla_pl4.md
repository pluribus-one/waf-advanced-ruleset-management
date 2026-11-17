# Evaluation Results for vanilla_pl4

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.96% (9996 / 10000)
	- **Wrong predictions:** 4

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 19.78% (7914 / 40000)
	- **Wrong predictions:** 32086

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.99% (14783 / 14785)
	- **Wrong predictions:** 2

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 19.05% (9942 / 52197)
	- **Wrong predictions:** 42255

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 98.08% (12848 / 13100)
	- **Wrong predictions:** 252

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.96% (2352 / 2353)
	- **Wrong predictions:** 1

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 68.32% (2638 / 3861)
	- **Wrong predictions:** 1223

### Performance

- **Accuracy:** 44.37%
- **Precision:** 34.60%
- **Recall:** 99.36%
- **F1 Score:** 51.33%

### Confusion Matrix

- **True Positives:** 39979
- **True Negatives:** 20494
- **False Positives:** 75564
- **False Negatives:** 259

### Totals
- **Correct:** 60473
- **Wrong:** 75823
- **Total:** 136296
