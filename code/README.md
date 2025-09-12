# README

Follow the steps below to set up, configure, and run the available components.

## Environment Setup

### 1. Android Studio Setup
1. Download Android Studio from [official website](https://developer.android.com/studio)
2. Install Android Studio following the installation wizard
3. Launch Android Studio and complete the initial setup

### 2. Android Virtual Device (AVD) Setup
1. Open Android Studio
2. Click "Tools" > "Device Manager" > "Create Virtual Device"
3. Select a device definition (e.g., Pixel 2)
4. Select a system image:
   - Choose x86 Images for better performance
   - Recommended: API 30 (Android 11.0) or higher
   - Download the system image if not available
5. Configure AVD settings:
   - Set device name
   - Adjust RAM size (recommended: 2GB or more)
   - Set internal storage (recommended: 2GB or more)
6. Click "Finish" to create the AVD

### 3. Physical Device Setup (Alternative)
1. Enable Developer Options on your Android device:
   - Go to Settings > About Phone
   - Tap "Build Number" 7 times
2. Enable USB debugging in Developer Options
3. Connect device via USB
4. Allow USB debugging on device when prompted

### 4. Python Environment

Create and activate a conda environment, then install dependencies:

```bash
cd /path/TraceDroid/code/tracedroid
conda create -n tracedroid python=3.10 -y
conda activate tracedroid
pip install -r requirements.txt
```

## Configurations

Edit `tracedroid/config.ini`:

```ini
[uiautomator2]
; android_device = <device_serial>   ; optional, required only for dynamic execution

[llm]
openai_base_url = <your_openai_base_url_or_https://api.openai.com/v1>
openai_api_key  = <your_api_key>
openai_model    = gpt-4o-mini
```

You can quickly validate your LLM connections:

```bash
python test_gpt_connection.py
```

Add apk and code files:

- APK file: put an APK into `code/tracedroid/apks/`. The demo `main.py` expects `apks/xx.apk` by default. Adjust as needed.
- Source Code Files: put source code in `repo_root/` path.

## Run

Run:

```bash
conda activate tracedroid
cd /path/TraceDroid/code/tracedroid
python main.py
```


## Heuristic Rule Examples

Below are provided some examples of heuristic rules in different categories. For the complete rules, please refer to the `tracedroid/heuristic_detection.py` document.

### 1. Null Pointer Exceptions

This type of rule is primarily used to detect unsafe access to objects that may be `null` without prior validation.

* **Rule 1.1: Uninitialized UI Component Access**
    * **Description:** Before calling a method of a UI component (such as `TextView` or `Button`), it is mandatory to check whether the component has been successfully initialized via `findViewById` or view binding. Directly accessing the component before `onViewCreated` in a Fragment or before the asynchronous layout loading is completed is a high-risk operation.

* **Rule 1.2: Object Access in Asynchronous Callbacks**
    * **Description:** When accessing external objects (especially member variables of an Activity/Fragment) in the callback methods (e.g., `onSuccess`, `onResponse`) of asynchronous operations such as network requests or database queries, you must first check whether the object has been destroyed due to lifecycle changes (e.g., screen rotation, page closure).

* **Rule 1.3: Iteration over API-Returned Collections**
    * **Description:** Before iterating over a collection or array returned by a method (especially those from APIs or system libraries) (e.g., using a for-each loop), a `null` check must be performed on the collection itself to prevent crashes caused by the interface returning `null` instead of an empty collection.


### 2. Runtime Exceptions and Error Handling

This type of rule focuses on identifying crashes caused by the lack of necessary exception handling or violations of regulations in specific runtime environments (e.g., the Android UI framework).

* **Rule 2.1: UI Update on Non-UI Thread**
    * **Description:** Any operation that modifies the properties of a UI component (e.g., `setText`, `setVisibility`) must be wrapped in `Activity.runOnUiThread()` or executed via a `Handler` associated with the main thread if its call chain may originate from a background thread.

* **Rule 2.2: Resource ID Validity Check**
    * **Description:** When using dynamically generated resource IDs or those obtained from external sources (e.g., `getResources().getDrawable(id)`), the operation must be wrapped in a `try-catch` block to catch `Resources.NotFoundException`, as the ID may be invalid or have been removed.

* **Rule 2.3: Guarded Type Casting**
    * **Description:** Before performing an explicit object type cast, the `instanceof` keyword must be used for checking to prevent a `ClassCastException` caused by a mismatch between the actual type of the object and the expected type.



### 3. External Integration and Compatibility

This type of rule aims to detect crashes caused by incompatibilities with device environments, system versions, or third-party libraries.

* **Rule 3.1: API Level Compatibility Check**
    * **Description:** Before calling any API introduced in a specific Android version, `Build.VERSION.SDK_INT` must be used to check whether the system version of the current device meets the minimum requirements, ensuring the app's compatibility on devices with older versions.

* **Rule 3.2: Runtime Permission Verification**
    * **Description:** Before performing an operation that requires dangerous permissions (e.g., accessing the camera, reading contacts), `Context.checkSelfPermission()` must be called to verify whether the permission has been granted; otherwise, a `SecurityException` may occur.


### 4. Concurrency and Resource Management

This type of rule is used to identify race conditions, resource leaks, and improper component state management issues in multi-threaded programming.

* **Rule 4.1: Fragment State-Safe Access**
    * **Description:** Before performing a transaction (e.g., `commit`) on a Fragment or calling its methods that require a context (e.g., `getContext()`), its lifecycle state must be checked—for example, using `isAdded()` or `isResumed()`—to prevent an `IllegalStateException` caused by operations when the Fragment is not attached to an Activity.

* **Rule 4.2: Atomic Access to Shared Variables**
    * **Description:** When a mutable variable is read from and written to by multiple threads simultaneously, the `synchronized` keyword, `volatile` keyword, or atomic classes from the `java.util.concurrent.atomic` package must be used to ensure the atomicity and visibility of operations, preventing data inconsistency.


* **Rule 4.3: Explicit Closing of Resource Objects**
    * **Description:** For resource objects that implement the `Closeable` interface (e.g., `Cursor`, `InputStream`, `OkHttp ResponseBody`), their `close()` method must be called in a `finally` block or a `try-with-resources` statement to avoid resource leaks.


### 5. Database Operation Issues

This type of rule mainly focuses on problems caused by improper database usage, such as query errors, data overflow, or misuse of ORM frameworks.

* **Rule 5.1: Database Transaction Size Limitation**
    * **Description:** When executing database transactions—especially when inserting large BLOB data—the data size should be checked to see if it is close to SQLite's `SQLITE_MAX_LENGTH` limit. For oversized data, file storage paths should be used instead of directly storing the data in the database.


* **Rule 5.2: Cursor Column Existence Check**
    * **Description:** Before retrieving data from a `Cursor` by column name, `getColumnIndex()` should be called first, and the return value should be checked to see if it is `-1`. This prevents an `IllegalArgumentException` caused by changes to the database table structure (e.g., columns being deleted or renamed).


