# Experiment Results

## RQ1&RQ2

The data of RQ1&RQ2: [google drive link](https://drive.google.com/file/d/1FfFeHIqTq9uEvQ3vxFXxhLki-i_HRXo9/view?usp=sharing)

This dataset supports the evaluation of **RQ1 (Detection Effectiveness and Coverage)** and **RQ2 (Ablation Study)** in the paper TraceDroid. It contains 70 confirmed crash bugs from 42 open-source Android applications, including their corresponding APK files and metadata (e.g., bug reports, fix links) to ensure full experiment reproducibility.


### Data Access

The dataset is hosted on Google Drive. You can download it via the following link:  
[Google Drive Download Link](https://drive.google.com/file/d/1FfFeHIqTq9uEvQ3vxFXxhLki-i_HRXo9/view?usp=sharing)  

After downloading, unzip the compressed file using standard tools to access the complete dataset.


### File Structure

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

#### Key Directories/Files

- **`apks/`**: Stores 70 Android APK files (named `1.apk` to `70.apk`). Each APK corresponds to a specific version of an open-source app that contains one confirmed crash bug. These APKs are used to run GUI testing experiments (TraceDroid, baselines, and ablation variants) for RQ1 and RQ2.  
- **`RQ1&RQ2.csv`**: A metadata file that links each crash bug to its original project, bug report, reproduction steps, and fix. This enables traceability and validation of the bugs used in the experiments.


### CSV File Description

The `RQ1&RQ2.csv` file has 5 columns, with one row per crash bug (matching the 70 APKs in `apks/`). The columns are defined as follows:

| Column Name   | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `index`       | Unique numerical ID for the crash bug (1–70), directly mapping to the APK filename (e.g., `index=10` corresponds to `10.apk`). |
| `github_link` | URL of the open-source app’s GitHub repository where the crash bug occurred. |
| `issue_link`  | URL to the original GitHub Issue report describing the crash bug (includes bug symptoms, user feedback, and initial reproduction notes). |
| `reproduce`   | Concise text summary of the **verified manual reproduction steps** for the crash bug (aligned with the steps used to validate experiment results in the paper). |
| `fix_link`    | URL to the GitHub Commit or Pull Request that fixes the crash bug (used to confirm the bug’s authenticity and resolution). |

## RQ3


RQ3 extends beyond controlled open-source datasets to validate TraceDroid’s real-world value. We tested TraceDroid alongside 5 top-performing baselines (selected from RQ1’s results) on popular Android apps from Google Play. The focus was on: 

- Identifying **previously unreported crash bugs** (not documented in public issue trackers).  
- Verifying bug validity through direct **developer feedback** (fixes or confirmations).  


### Dataset Selection Criteria

To ensure reproducibility and representativeness, apps were selected using strict filters:  

| Criterion | Description |  
|-----------|-------------|  
| Initial Pool | 200 randomly selected popular apps from Google Play, spanning categories (e.g., Productivity, Fitness, Finance) to ensure functional diversity. |  
| Filter 1: Decompilability | Apps must be decompiled to retrieve source code (required for TraceDroid’s heuristic-based suspicious code detection). |  
| Filter 2: UI Accessibility | UIAutomator (Android testing tool) must extract both **view hierarchies** (for widget identification) and **GUI screenshots** (for runtime validation). |  
| Final Dataset | 116 apps remained post-filtering, with download volumes ranging from 500K+ to 5M+. |  


### Full RQ3 Experimental Data Table

Below is the complete dataset of detected bugs (reproduced from Table 3 in the source document), including app details, bug status, and baseline detection results.  

| ID  | App Name          | Download | Category   | Version  | Status     | TimeM | Comb | Huma | Guard | BugH |  
|-----|-------------------|----------|------------|----------|------------|-------|------|------|-------|------|  
| 1   | Journal           | 5M+      | Product    | 131      | Status     |       |      |      |       |      |  
| 2   | Height Increase   | 5M+      | Fitness    | 1.1.8    | Fixed      |       |      |      |       |      |  
| 3   | Offline Music     | 5M+      | Music      | 1.34.1   | Fixed      |       |      |      | *     | *    |  
| 4   | DailyLife         | 5M+      | Lifestyle  | 4.3.1    | Fixed      |       |      |      |       |      |  
| 5   | Easy Notes        | 1M+      | Product    | 1.3.23   | Fixed      |       | *    |      |       | *    |  
| 6   | Expense Tracker   | 1M+      | Finance    | 1.01     | Fixed      |       |      |      |       |      |  
| 7   | My Cash           | 1M+      | Enter      | 38       | Confirmed  |       |      |      | *     |      |  
| 8   | BetterMe          | 1M+      | Health     | 9.31     | Fixed      |       | *    |      |       | *    |  
| 9   | Daily Yoga        | 1M+      | Sport      | 1.2.1    | Fixed      |       |      |      |       |      |  
| 10  | Daily Routine     | 1M+      | Tool       | 1.1.10   | Confirmed  |       |      |      |       |      |  
| 11  | FreeYourMusic     | 1M+      | Music      | 9.17.0   | Fixed      |       |      | *    |       |      |  
| 12  | Weather Forecast  | 1M+      | Weather    | 2.1      | Confirmed  |       |      |      |       | *    |  
| 13  | Add Text          | 1M+      | Photo      | 2.7      | Fixed      | *     |      |      | *     |      |  
| 14  | SideChef          | 1M+      | Food       | 5.31.1   | Fixed      |       |      |      |       |      |  
| 15  | RISE              | 1M+      | Lifestyle  | 1.78.33  | Fixed      |       |      |      |       |      |  
| 16  | Timetable         | 1M+      | Education  | 2.3.1    | Confirmed  |       |      |      |       |      |  
| 17  | Daily Planner     | 1M+      | Product    | 63       | Fixed      | *     | *    | *    | *     | *    |  
| 18  | Headout           | 1M+      | Travel     | 8.19.0   | Confirmed  |       |      |      |       |      |  
| 19  | MyMoney           | 1M+      | Finance    | 5.7      | Fixed      |       |      |      |       |      |  
| 20  | Quabble           | 500K+    | Health     | 2.6.8    | Confirmed  |       |      |      |       | *    |  
| 21  | EdrawMind         | 500K+    | Tool       | 7.9.1    | Fixed      |       |      |      |       |      |  

*Notes: \* indicates the baseline detected the bug; empty cells mean the bug was not detected. Baselines are abbreviated as follows: TimeM (Time-Machine), Comb (ComboDroid), Huma (Humanoid), Guard (Guardian), BugH (BugHunter).*  


### Data Fields Explanation

Each column in the table is defined below for clarity:  

| Field       | Description                                                                 |  
|-------------|-----------------------------------------------------------------------------|  
| `ID`        | Unique identifier for each detected bug (1–21).                             |  
| `App Name`  | Name of the Google Play app where the bug was found.                        |  
| `Download`  | App’s estimated download volume (indicates popularity).                     |  
| `Category`  | App’s functional category (per Google Play’s classification).               |  
| `Version`   | Exact app version tested (critical for reproducing bugs).                   |  
| `Status`    | Bug validation status (see Section 5 for definitions).                     |  
| `TimeM`     | Whether Time-Machine (random/rule-based baseline) detected the bug.         |  
| `Comb`      | Whether ComboDroid (model-based baseline) detected the bug.                 |  
| `Huma`      | Whether Humanoid (learning-based baseline) detected the bug.                |  
| `Guard`     | Whether Guardian (LLM-based baseline) detected the bug.                     |  
| `BugH`      | Whether BugHunter (bug-driven baseline) detected the bug.                   |  


### Bug Status Definitions

Bugs were classified based on direct feedback from app developers:  

| Status     | Definition                                                                 |  
|------------|-----------------------------------------------------------------------------|  
| `Fixed`    | Developer confirmed the bug and released an update to resolve it (15/21 bugs). |  
| `Confirmed`| Developer acknowledged the bug as valid but had not fixed it at submission (6/21 bugs). |  
| `Status`   | No developer feedback recorded for this entry (ID 1 only).                  |  


### Key Experimental Results

From the dataset, the following key findings validate TraceDroid’s utility:  
- **Total Unknown Bugs**: TraceDroid detected 21 previously unreported crash bugs across 116 apps.  
- **Developer Validation**: 100% of detected bugs were validated (15 fixed, 6 confirmed).  
- **Baseline Comparison**: The top-performing baseline (BugHunter) detected only 6 of these 21 bugs—all were a subset of TraceDroid’s detections. No other baseline found additional bugs.  


### Access to Supplementary Materials

All RQ3 supplementary materials are publicly available in the TraceDroid repository, including:  
- **Bug Reproduction Guides**: Step-by-step instructions to replicate each detected bug.  
- **Developer Feedback Screenshots**: Emails/messages from developers confirming/fixing bugs.  
- **Test Logs**: Raw execution logs for TraceDroid and baselines (with bug detection timestamps).  
