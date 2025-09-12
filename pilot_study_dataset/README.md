# README

The data of pilot study: [google drive link](https://drive.google.com/file/d/19o99vec36Z4VFzwBGJ_iLlY30cccMFqs/view?usp=sharing)

This dataset supports the motivational study of TraceDroid, focusing on analyzing real-world crash bug patterns in Android applications. The data is curated to identify recurrent crash root causes, which directly inform the design of TraceDroid's heuristic rules for suspicious code detection.

## Data Collection

### 1. Source Selection

We randomly selected **300 open-source Android apps** from GitHub, focusing on projects that meet the following criteria:

- Active maintenance (evidenced by at least 100 GitHub stars or 50 commits to ensure project relevance).
- Publicly accessible issue trackers with explicit labels (e.g., "crash", "bug") to identify crash-related reports.
- Linked code repositories to map issue reports to concrete code modifications (critical for validating crash root causes).

### 2. Filtering Criteria

To ensure data quality and alignment with the study’s goal of analyzing actionable crash bugs, we applied two core filters:

1. **Crash Bug Validation**: The issue report must explicitly describe an app crash (e.g., "force close", "unexpected termination", or include stack trace snippets for exceptions like `NullPointerException`).
2. **Code Traceability**: The report must be linked to a GitHub commit (via "Fixes #XXX" or similar annotations) that directly resolves the crash, enabling verification of the bug’s root cause through code changes.

### 3. Manual Verification

Two authors independently reviewed each candidate issue to confirm:

- The issue reflects a genuine crash (not a feature request, performance concern, or UI glitch).
- The linked commit addresses the crash (not unrelated refactoring or minor fixes).
A third author resolved discrepancies until **full consensus** was reached, reducing the initial 5,783 issues to 1,639 valid crash bugs.


## Crash Bug Categorization

Based on the **card sorting method**, we classified the 1,639 crash bugs into **5 major categories** (and subcategories) by root cause, triggering context, and functional scenario. This classification directly informed TraceDroid’s heuristic rule design and aligns with real-world mobile app crash distributions:

### 1. Null Pointer Exceptions (29%)

Crashes from accessing uninitialized/null objects without validation.  

Subcategories:

- GUI binding failures (e.g., accessing views before data loading completes).
- Asynchronous data access (e.g., callbacks referencing released objects).
- Collection/array null access (e.g., list access without null checks).  

**Typical Scenarios**: News feeds, media galleries, chat lists (data-heavy UI updates).

### 2. Runtime Exceptions and Error Handling (27%)

Crashes from missing or insufficient exception handling during critical operations.  

Subcategories:

- UI thread violations (e.g., updating UI from background threads).
- Resource misuse (e.g., invalid resource IDs, missing assets like images).
- Type/encoding errors (e.g., failed type casting, character encoding mismatches).  

**Typical Scenarios**: Background uploads, scans, data backups.

### 3. External Integration and Compatibility (19%)

Crashes from incompatibilities with external systems or platforms.  

Subcategories:

- Third-party API changes (e.g., unadapted updates to Google Maps/Pay APIs).
- Platform-specific behaviors (e.g., Android 12+ permission changes breaking older code).
- Permission/manifest issues (e.g., missing required permissions, invalid manifest declarations).  

**Typical Scenarios**: Apps relying on external services (payment, location) or hardware integrations.

### 4. Concurrency and Resource Management (14%)

Crashes from improper handling of concurrent processes or system resources.  

Subcategories:

- Repeated component start (e.g., multiple `startService()` calls in quick succession).
- State check omissions (e.g., operating on an uninitialized activity).
- Non-atomic variable access (e.g., race conditions in shared resource access).  

**Typical Scenarios**: Content sharing, user status updates (shared resource-intensive features).

### 5. Database Operation Issues (11%)

Crashes from database misuse or exceeding system limits.  

Subcategories:

- Data size limit exceeded (e.g., BLOBs larger than SQLite constraints).
- Incorrect query/comparator (e.g., invalid SQL, broken sorting logic).
- ORM misuse (e.g., improper Room/Hibernate API calls).  

**Typical Scenarios**: Note-taking apps, accounting tools (data-persistent applications).


## Dataset Structure
The dataset is organized in **CSV/JSON format** with the following fields per crash bug entry, aligned with the structure specified:

| Field               | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `app_name`          | Name of the Android app|
| `github_link`       | Direct URL to the app’s GitHub repository |
| `fdroid_link`       | URL to the app’s F-Droid page |
| `app_desc`          | Brief description of the app’s core functionality |
| `category`          | Functional category of the app |
| `issue_url`         | Direct URL to the GitHub issue report |
| `issue_title`       | Title of the GitHub issue |
| `issue_content`     | Full text of the issue report |

## Data Access

The data can be viewed at [google drive link](https://drive.google.com/file/d/19o99vec36Z4VFzwBGJ_iLlY30cccMFqs/view?usp=sharing).