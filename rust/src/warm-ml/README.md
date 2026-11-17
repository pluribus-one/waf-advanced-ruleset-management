_(Written by a human)_

# About the project

## The problem

The Core Rule Set (CRS) allows users to select 4 paranoia levels (PL) to optimize its use, starting from the most permissive level (1) to the strictest level (4). Therefore PL1 will produce fewer false positives, but will also block fewer malicious requests. On the other hand, PL4 will surely give more false positives, but will also block more malicious requests.

### Ok, but is it really that bad to just use paranoia levels to optimize it?

You can see how CRS actually performs with [PL1](data/results/vanilla_pl1.md) and [PL4](data/results/vanilla_pl4.md) yourself. It's clear that PL4 is too strict for many legitimate requests. Instead, PL1 is a good starting point in general, but still not permissive enough for some legitimate requests and not strict enough for some malicious ones.

## The solution

### Project goal

The project aims to

- (1) reduce false positives while using the CRS rules

- (2) without compromising the effectiveness too much

These goals are ordered by priority which means that reducing false positives is preferred over increasing true positives.

### The actual project

In practice, the project is a Rust implementation of a machine learning (ML) model trained to understand whether a combination of triggered rules from an HTTP request indicates a legitimate or malicious request.

The final result is a Rust library that, through a Web Application Firewall (WAF), receives the CRS rules triggered by an HTTP request and uses the ML model to determine whether the request is safe or not.

# Project structure

- README.md - This file
- Cargo.toml - Cargo dependencies and project definitions
- data - A folder for everything that is not library code
	- crs - The Core Rule Set used by the model to evaluate requests
	- features - A folder containing the generated feature datasets
	- ml_dataset - A folder containing the datasets used during training and testing
		- closed - A folder containing datasets that can't be shared or found publicly
		- open - A folder with datasets which can be found online
		- gen-open-dataset.sh - A bash script for generating the _open_ folder
	- models - A folder containing all trained models ready to be loaded and used. The naming convention is *warm\_{usage_percentage}\_{legitimate_percentage}.bin* . For details, check [TODO]()
	- results - A folder containing all evaluation results and generated plots. The naming convention is the same as the one used for the **model** folder.
	- setup - A folder containing the configuration files needed for the model to correctly use the WAF and the CRS.
- examples - A folder containing some library usage examples
- src - The folder containing all library source code. For library details check [TODO]()
- tests - A folder containing the library test files. Currently used for training and testing.

# Q&A
## How to train a model?

```sh
cargo test train_{algorithm}_{usage_percentage}_{legitimate_percentage} --release
```

This command will generate a *warm\_{algorithm}\_{usage_percentage}\_{legitimate_percentage}.bin* file in the **models** folder and a *warm\_{algorithm}\_{usage_percentage}\_{legitimate_percentage}.png* image in the **results** folder with a plot.

## How to test a model?

```sh
cargo test dataset_{algorithm}_{usage_percentage}_{legitimate_percentage} --release
```

This command will generate a *warm_{algorithm}\_{usage_percentage}\_{legitimate_percentage}.txt* file in the **results** folder containing the test results.

## I have just cloned the repository. How can I test/train a model?

```sh
# Download public datasets
cd owasp-warm/rust/src/warm-ml/data/ml_dataset
bash gen-open-dataset.sh

# Train and test a warm_lr_100_050 model
cd ../..
cargo test train_lr_100_050 --release -- --nocapture && cargo test dataset_lr_100_050 --release -- --nocapture
```

## What are {algorithm}, {usage_percentage}, {legitimate_percentage} ?

They are placeholders. Their meaning is explained below:

- **{algorithm}**: The algorithm to use for training or that was used to train the model. It can be **svm** for the *Support Vector Machine algorithm* or **lr** for the *Logistic Regression* algorithm.

- **{usage_percentage}**: This is the dataset usage percentage. It can be used to create simpler or smarter models. For example a value of 50 means *"Take 50% of the whole dataset and use it to train the model"*. Since this is a percentage the value must be a number between 0 and 100. To understand how this value is actually used you can check [TODO]() .

- **{legitimate_percentage}**: This is the percentage of legitimate requests of the used dataset. Can be used to decrease or increase the number of legitimate requests used in training, which means that you can create an unbalanced dataset with more or fewer legitimate requests than malicious requests. For example a value of 60 means *"Given the selected dataset usage percentage, take a number of requests which creates a dataset composed of 60% of legitimate requests and a 40% of malicious requests"*. Since this is a percentage the value must be a number between 0 and 100. To understand how this value is actually used you can check [TODO]() .

