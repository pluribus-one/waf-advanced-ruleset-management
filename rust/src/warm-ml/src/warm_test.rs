use std::fs;

use crate::{dataset::{WarmDataset, WarmDatasetFile}, ml_model::{WarmFeatureDataset, WarmModel}, waf_engines::WafEngine, warm::{Warm, WarmEvaluator}};

pub struct WarmTestConfusionMatrix {
	false_positive: usize,
    true_positive: usize,
    false_negative: usize,
    true_negative: usize,
	evaluations: usize,
}
impl WarmTestConfusionMatrix {
	fn false_positive_count(&self) -> usize	{
		self.false_positive
	}
    fn true_positive_count(&self) -> usize{
		self.true_positive
	}
    fn false_negative_count(&self) -> usize{
		self.false_negative
	}
    fn true_negative_count(&self) -> usize{
		self.true_negative
	}
	fn evaluations_count(&self) -> usize {
		self.evaluations
	}
	fn correct_count(&self) -> usize {
		self.true_negative + self. true_positive
	}
	fn wrong_count(&self) -> usize {
		self.false_negative + self.false_positive
	}
}

pub struct WarmTestUtils;
impl WarmTestUtils {
	fn accuracy(cm: &WarmTestConfusionMatrix) -> f32 {
        if cm.evaluations_count() == 0 {
            return 0.0;
        }

        (cm.true_positive_count() + cm.true_negative_count()) as f32
            / cm.evaluations_count() as f32
    }

    fn precision(cm: &WarmTestConfusionMatrix) -> f32 {
        cm.true_positive_count() as f32 / (cm.true_positive_count() + cm.false_positive_count()) as f32
    }

    fn recall(cm: &WarmTestConfusionMatrix) -> f32 {
        cm.true_positive_count() as f32 / (cm.true_positive_count() + cm.false_negative_count()) as f32
    }

    fn f1_score(cm: &WarmTestConfusionMatrix) -> f32 {
        let p = Self::precision(cm);
        let r = Self::recall(cm);

        if p + r == 0.0 {
            return -1.0;
        }

        2.0 * p * r / (p + r)
    }
}

pub trait WarmTest: ToString{
    type Data;

    fn test<E: WarmEvaluator>(test_name: String, evaluator: &E, data: &Self::Data) -> Self;
	/// Adds .md as extension to the file
    fn save_as_markdown(&self, file_path: &str){
		let md = self.to_markdown();
		fs::write(format!("{}.md", file_path), md).expect("Failed to save markdown report");
	}
    fn to_markdown(&self) -> String;    
	fn get_confusion_matrix(&self) -> &WarmTestConfusionMatrix;

	fn accuracy(&self) -> f32;
	fn precision(&self) -> f32;
	fn recall(&self) -> f32;
	fn f1_score(&self) -> f32;
}
pub struct WarmDatasetTest{
	name: String,
	confusion_matrix: WarmTestConfusionMatrix,
    test_results: Vec<WarmFileTest>,
}

impl WarmDatasetTest {
	pub fn from_files_test(test_name: String, files_test: Vec<WarmFileTest>) -> Self {
		let mut confusion_matrix = WarmTestConfusionMatrix { 
			false_positive: 0, true_positive: 0, false_negative: 0, true_negative: 0, evaluations: 0  
		};

        for test_result in &files_test {
			let test_cm = test_result.get_confusion_matrix();

            confusion_matrix.false_negative += test_cm.false_negative;
            confusion_matrix.true_negative += test_cm.true_negative;
            confusion_matrix.false_positive += test_cm.false_positive;
            confusion_matrix.true_positive += test_cm.true_positive;
			confusion_matrix.evaluations += test_cm.evaluations;
        }

        Self {
			name: test_name,
            confusion_matrix,
            test_results: files_test,
        }
	}
}

impl WarmTest for WarmDatasetTest {
    type Data = WarmDataset;

    fn test<E: WarmEvaluator>(test_name: String, evaluator: &E, data: &WarmDataset) -> Self{
        let files = data.get_files();
        let mut test_results = Vec::<WarmFileTest>::new();

		let mut confusion_matrix = WarmTestConfusionMatrix { 
			false_positive: 0, true_positive: 0, false_negative: 0, true_negative: 0, evaluations: 0  
		};

        for file in files {
            let test_result = WarmFileTest::test(file.get_normalized_name(), evaluator, file);
			let test_cm = test_result.get_confusion_matrix();

            confusion_matrix.false_negative += test_cm.false_negative;
            confusion_matrix.true_negative += test_cm.true_negative;
            confusion_matrix.false_positive += test_cm.false_positive;
            confusion_matrix.true_positive += test_cm.true_positive;
			confusion_matrix.evaluations += test_cm.evaluations;

			test_results.push(test_result);
        }

        Self {
			name: test_name,
            confusion_matrix,
            test_results,
        }
    }

    fn to_markdown(&self) -> String{
        let mut md = format!(
            "# Evaluation Results for {}\n\n## Per-Dataset Results\n",
            self.name,
        );

		for result in &self.test_results {
            md.push_str(&result.to_markdown());
        }

		md.push_str(format!("
### Performance

- **Accuracy:** {:.2}%
- **Precision:** {:.2}%
- **Recall:** {:.2}%
- **F1 Score:** {:.2}%

### Confusion Matrix

- **True Positives:** {}
- **True Negatives:** {}
- **False Positives:** {}
- **False Negatives:** {}

### Totals
- **Correct:** {}
- **Wrong:** {}
- **Total:** {}
",
		self.accuracy() * 100.0,
		self.precision() * 100.0,
		self.recall() * 100.0,
		self.f1_score() * 100.0,
		self.confusion_matrix.true_positive,
		self.confusion_matrix.true_negative,
		self.confusion_matrix.false_positive,
		self.confusion_matrix.false_negative,
		self.confusion_matrix.correct_count(),
		self.confusion_matrix.wrong_count(),
		self.confusion_matrix.evaluations_count()
        ).as_str());

		md
    }
	
	fn get_confusion_matrix(&self) -> &WarmTestConfusionMatrix {
		&self.confusion_matrix
	}
	
	fn accuracy(&self) -> f32 {
		WarmTestUtils::accuracy(&self.confusion_matrix)		
	}
	
	fn precision(&self) -> f32 {
		WarmTestUtils::precision(&self.confusion_matrix)		
	}
	
	fn recall(&self) -> f32 {
		WarmTestUtils::recall(&self.confusion_matrix)		
	}
	
	fn f1_score(&self) -> f32 {
		WarmTestUtils::f1_score(&self.confusion_matrix)
	}
    
}
impl ToString for WarmDatasetTest {
    fn to_string(&self) -> String {
        self.to_markdown()	//TODO
    }
}

pub struct WarmFileTest{
    name: String,
	label: bool,
	confusion_matrix: WarmTestConfusionMatrix,
}

impl WarmTest for WarmFileTest {
    type Data = WarmDatasetFile;
	
	fn test<E: WarmEvaluator>(test_name: String, evaluator: &E, data: &WarmDatasetFile) -> Self{
		let mut false_positive: usize = 0;
        let mut true_positive: usize = 0;
        let mut false_negative: usize = 0;
        let mut true_negative: usize = 0;
		let mut evaluations: usize = 0;
		let expected = data.get_label();
		
		for sample in data.get_samples() {
			let result = evaluator.evaluate(sample).is_malicious();
			
			match (expected,result) {
				(true, true) => true_positive += 1,
				(true, false) => false_negative += 1,
				(false, true) => false_positive += 1,
				(false, false) => true_negative += 1,
			}

			evaluations += 1;
		}
		
		Self {
			name: test_name,
			label: expected,
			confusion_matrix: WarmTestConfusionMatrix { false_positive, true_positive, false_negative, true_negative, evaluations },
		}
	}
	
	fn to_markdown(&self) -> String {
		let label_string = match self.label {
			true => "Malicious",
			false => "Legitimate"
		};

		format!(
"
**{}**
	- **Label:** {label_string}
	- **Correct predictions:** {:.2}% ({:.2} / {:.2})
	- **Wrong predictions:** {:.2}
", 	
		self.name, 
		(self.confusion_matrix.correct_count() as f32/self.confusion_matrix.evaluations as f32) * 100.0,
		self.confusion_matrix.correct_count(),
		self.confusion_matrix.evaluations,
		self.confusion_matrix.wrong_count()).to_string()		
	}
	
	fn get_confusion_matrix(&self) -> &WarmTestConfusionMatrix {
		&self.confusion_matrix
	}
	
	fn accuracy(&self) -> f32 {
		WarmTestUtils::accuracy(&self.confusion_matrix)		
	}
	
	fn precision(&self) -> f32 {
		WarmTestUtils::precision(&self.confusion_matrix)		
	}
	
	fn recall(&self) -> f32 {
		WarmTestUtils::recall(&self.confusion_matrix)		
	}
	
	fn f1_score(&self) -> f32 {
		WarmTestUtils::f1_score(&self.confusion_matrix)
	}
}

impl ToString for WarmFileTest {
    fn to_string(&self) -> String {
        self.to_markdown() //TODO
    }
}

impl WarmFileTest {
	/// `data` is expected to be a [`WarmFeatureDataset`] extracted from a [`WarmDatasetFile`]
	pub fn test_with_feature_dataset<W: WafEngine, M: WarmModel>(test_name: String, warm: &Warm<W, M>, data: &WarmFeatureDataset) -> Self {
		let mut false_positive: usize = 0;
        let mut true_positive: usize = 0;
        let mut false_negative: usize = 0;
        let mut true_negative: usize = 0;
		let mut evaluations: usize = 0;
		let label = data.get_labels_list()[0];

		let dataset_rows = data.get_features_list().rows();
		
		for sample in dataset_rows {
			let result = warm.evaluate_features(sample).is_malicious();
			
			match (label, result) {
				(true, true) => true_positive += 1,
				(true, false) => false_negative += 1,
				(false, true) => false_positive += 1,
				(false, false) => true_negative += 1,
			}

			evaluations += 1;
		}
		
		Self {
			name: test_name,
			label: label,
			confusion_matrix: WarmTestConfusionMatrix { false_positive, true_positive, false_negative, true_negative, evaluations },
		}
	}
}