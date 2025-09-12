#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Analysis Tool
Analyze APK files and generate a detailed analysis report
"""

import os
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
import sys

# Add current directory to Python path to import the app module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import App


class APKAnalyzer:
    """APK Analyzer class"""
    
    def __init__(self, apk_path, output_dir="apk_analysis"):
        """
        Initialize the APK analyzer
        
        Args:
            apk_path (str): Path to the APK file
            output_dir (str): Output directory
        """
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.logger = self._setup_logger()
        
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get the APK file name without extension
        self.apk_name = Path(apk_path).stem
        
    def _setup_logger(self):
        """Set up the logger"""
        logger = logging.getLogger('APKAnalyzer')
        logger.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(console_handler)
        
        return logger
    
    def analyze_apk(self):
        """
        Analyze the APK file
        
        Returns:
            dict: Analysis result dictionary
        """
        self.logger.info(f"Start analyzing APK file: {self.apk_path}")
        
        try:
            # Create App instance
            app = App(self.apk_path, self.output_dir)
            
            # Collect analysis data
            analysis_data = {
                "analysis_info": {
                    "apk_path": self.apk_path,
                    "analysis_time": datetime.now().isoformat(),
                    "analyzer_version": "1.0.0"
                },
                "basic_info": {
                    "package_name": app.get_package_name(),
                    "app_name": app.app_name,
                    "main_activity": app.get_main_activity(),
                    "file_hashes": {
                        "md5": app.hashes[0],
                        "sha1": app.hashes[1],
                        "sha256": app.hashes[2]
                    }
                },
                "permissions": {
                    "total_count": len(app.permissions),
                    "permissions_list": list(app.permissions)
                },
                "activities": {
                    "total_count": len(app.activities),
                    "activities_list": list(app.activities)
                },
                "broadcasts": {
                    "total_count": len(app.possible_broadcasts),
                    "broadcasts_list": [str(broadcast) for broadcast in app.possible_broadcasts]
                },
                "intents": {
                    "start_intent": str(app.get_start_intent()),
                    "stop_intent": str(app.get_stop_intent())
                },
                "security_analysis": {
                    "permission_risk_level": self._analyze_permission_risk(app.permissions),
                    "dangerous_permissions": self._get_dangerous_permissions(app.permissions)
                }
            }
            
            self.logger.info("APK analysis completed")
            return analysis_data
            
        except Exception as e:
            self.logger.error(f"Error occurred while analyzing APK: {str(e)}")
            raise
    
    def _analyze_permission_risk(self, permissions):
        """
        Analyze permission risk level
        
        Args:
            permissions (list): List of permissions
            
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH)
        """
        dangerous_permissions = self._get_dangerous_permissions(permissions)
        
        if len(dangerous_permissions) == 0:
            return "LOW"
        elif len(dangerous_permissions) <= 3:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _get_dangerous_permissions(self, permissions):
        """
        Get list of dangerous permissions
        
        Args:
            permissions (list): List of permissions
            
        Returns:
            list: List of dangerous permissions
        """
        dangerous_permissions = [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.SEND_SMS",
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION"
        ]
        
        return [perm for perm in permissions if perm in dangerous_permissions]
    
    def save_analysis_report(self, analysis_data):
        """
        Save analysis report to a JSON file
        
        Args:
            analysis_data (dict): Analysis data
            
        Returns:
            str: Saved file path
        """
        output_file = os.path.join(self.output_dir, f"{self.apk_name}_analysis.json")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Analysis report saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error occurred while saving report: {str(e)}")
            raise
    
    def run_analysis(self):
        """
        Run the complete APK analysis workflow
        
        Returns:
            str: Generated report file path
        """
        self.logger.info("Start APK analysis workflow")
        
        # Analyze APK
        analysis_data = self.analyze_apk()
        
        # Save report
        report_path = self.save_analysis_report(analysis_data)
        
        self.logger.info("APK analysis workflow completed")
        return report_path


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='APK Analysis Tool')
    parser.add_argument('apk_path', help='Path to the APK file')
    parser.add_argument('-o', '--output', default='apk_analysis', 
                       help='Output directory (default: apk_analysis)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose mode')
    
    args = parser.parse_args()
    
    # Check if the APK file exists
    if not os.path.exists(args.apk_path):
        print(f"Error: APK file does not exist: {args.apk_path}")
        sys.exit(1)
    
    # Check file extension
    if not args.apk_path.lower().endswith('.apk'):
        print(f"Warning: The file may not be in APK format: {args.apk_path}")
    
    try:
        # Create analyzer and run analysis
        analyzer = APKAnalyzer(args.apk_path, args.output)
        report_path = analyzer.run_analysis()
        
        print(f"\n✅ APK analysis completed!")
        print(f"📄 Report file: {report_path}")
        
    except Exception as e:
        print(f"❌ An error occurred during analysis: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
