# Evaluation Results for warm_lr_100_40

## Per-Dataset Results

**msan_sqli_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.56% (9956 / 10000)
	- **Wrong predictions:** 44

**msan_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 94.86% (37944 / 40000)
	- **Wrong predictions:** 2056

**openappsec_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 96.59% (14281 / 14785)
	- **Wrong predictions:** 504

**openappsec_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.64% (51489 / 52197)
	- **Wrong predictions:** 708

**payload-all-the-things_test**
	- **Label:** Malicious
	- **Correct predictions:** 95.30% (12484 / 13100)
	- **Wrong predictions:** 616

**http_params_malicious_test**
	- **Label:** Malicious
	- **Correct predictions:** 99.87% (2350 / 2353)
	- **Wrong predictions:** 3

**http_params_legitimate_test**
	- **Label:** Legitimate
	- **Correct predictions:** 98.34% (3797 / 3861)
	- **Wrong predictions:** 64

### Performance

- **Accuracy:** 97.07%
- **Precision:** 93.25%
- **Recall:** 97.10%
- **F1 Score:** 95.14%

### Confusion Matrix

- **True Positives:** 39071
- **True Negatives:** 93230
- **False Positives:** 2828
- **False Negatives:** 1167

### Totals
- **Correct:** 132301
- **Wrong:** 3995
- **Total:** 136296
