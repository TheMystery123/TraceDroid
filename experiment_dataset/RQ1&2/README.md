# README

This dataset supports the evaluation of **RQ1 (Detection Effectiveness and Coverage)** and **RQ2 (Ablation Study)** in the paper TraceDroid. It contains 70 confirmed crash bugs from 42 open-source Android applications, including their corresponding APK files and metadata (e.g., bug reports, fix links) to ensure full experiment reproducibility.


## Data Access

The dataset is hosted on Google Drive. You can download it via the following link:  
[Google Drive Download Link](https://drive.google.com/file/d/1FfFeHIqTq9uEvQ3vxFXxhLki-i_HRXo9/view?usp=sharing)  

After downloading, unzip the compressed file using standard tools to access the complete dataset.


## File Structure

After unzipping, the dataset follows this 2-level structure:

```
.
├── apks
│   ├── 1.apk
│   ├── 2.apk
│   ├── 3.apk
│   ├── ... (70 APK files total, named 1.apk to 70.apk)
│   ├── 69.apk
│   └── 70.apk
└── RQ1&RQ2.csv
```

### Key Directories/Files

- **`apks/`**: Stores 70 Android APK files (named `1.apk` to `70.apk`). Each APK corresponds to a specific version of an open-source app that contains one confirmed crash bug. These APKs are used to run GUI testing experiments (TraceDroid, baselines, and ablation variants) for RQ1 and RQ2.  
- **`RQ1&RQ2.csv`**: A metadata file that links each crash bug to its original project, bug report, reproduction steps, and fix. This enables traceability and validation of the bugs used in the experiments.


## CSV File Description

The `RQ1&RQ2.csv` file has 5 columns, with one row per crash bug (matching the 70 APKs in `apks/`). The columns are defined as follows:

| Column Name   | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `index`       | Unique numerical ID for the crash bug (1–70), directly mapping to the APK filename (e.g., `index=10` corresponds to `10.apk`). |
| `github_link` | URL of the open-source app’s GitHub repository where the crash bug occurred. |
| `issue_link`  | URL to the original GitHub Issue report describing the crash bug (includes bug symptoms, user feedback, and initial reproduction notes). |
| `reproduce`   | Concise text summary of the **verified manual reproduction steps** for the crash bug (aligned with the steps used to validate experiment results in the paper). |
| `fix_link`    | URL to the GitHub Commit or Pull Request that fixes the crash bug (used to confirm the bug’s authenticity and resolution). |