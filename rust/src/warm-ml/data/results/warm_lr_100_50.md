# Evaluation Results for warm_lr_100_50

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.55% (9955 / 10000)
	- **Wrong predictions:** 45

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 96.30% (38521 / 40000)
	- **Wrong predictions:** 1479

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 96.50% (14267 / 14785)
	- **Wrong predictions:** 518

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.76% (51551 / 52197)
	- **Wrong predictions:** 646

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 95.19% (12470 / 13100)
	- **Wrong predictions:** 630

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.87% (2350 / 2353)
	- **Wrong predictions:** 3

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.34% (3797 / 3861)
	- **Wrong predictions:** 64

### Performance

- **Accuracy:** 97.52%
- **Precision:** 94.69%
- **Recall:** 97.03%
- **F1 Score:** 95.85%

### Confusion Matrix

- **True Positives:** 39042
- **True Negatives:** 93869
- **False Positives:** 2189
- **False Negatives:** 1196

### Totals
- **Correct:** 132911
- **Wrong:** 3385
- **Total:** 136296
