import os
from typing import List, Dict, Any, Tuple
import networkx as nx

from app import App
from utils import list_all_files, extract_android_widgets_from_xml
from prompts import get_planning_prompt
from llm_api import OpenAIAPI


def heuristic_detection_placeholder() -> Dict[str, Any]:
    """
    Placeholder for Heuristic rule-based detection.
    Returns a mock code segment with symbols we can match.
    """
    return {
        'functions': ['onLoginClick', 'openSettings'],
        'methods': ['submit', 'startGame'],
        'classes': ['MainActivity', 'SettingsActivity'],
        'variables': ['login', 'settings']
    }


def extract_keywords_from_code_segment(code_segment: Dict[str, List[str]]) -> List[str]:
    keywords = []
    for key in ['functions', 'methods', 'classes', 'variables']:
        keywords.extend(code_segment.get(key, []))
    # Normalize
    cleaned = list({k.strip().lower() for k in keywords if k and isinstance(k, str)})
    return cleaned


def gui_widget_association(code_segment: Dict[str, Any], android_repo_root: str) -> List[Dict[str, Any]]:
    """
    Scan all XML layout files in the given Android repo directory and find widgets whose
    id/text matches any symbol in the code segment.
    """
    keywords = extract_keywords_from_code_segment(code_segment)
    widgets: List[Dict[str, Any]] = []
    for file_path in list_all_files(android_repo_root):
        if not file_path.lower().endswith(('.xml',)):
            continue
        for w in extract_android_widgets_from_xml(file_path):
            name_pool = [w.get('id'), w.get('text')]
            if any(n and str(n).lower() in keywords for n in name_pool):
                widgets.append(w)
    return widgets


def interaction_path_backtracking(widgets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Backtrack minimal context: widget, xml path, and approximate page name (derived from file name).
    """
    results = []
    for w in widgets:
        xml_path = w.get('xml_path', '')
        page_name = os.path.splitext(os.path.basename(xml_path))[0]
        results.append({
            'widget': w,
            'page': page_name,
            'layout_file': xml_path
        })
    return {
        'tracebacks': results
    }


def build_atg_from_app(apk_path: str) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Treat ATG as a variable; here we construct a simple graph from activities.
    """
    app = App(apk_path)
    activities = list(app.activities)
    G = nx.DiGraph()
    for a in activities:
        G.add_node(a)
    # Create a simple chain and a few chords as a dummy ATG
    for i in range(len(activities) - 1):
        G.add_edge(activities[i], activities[i + 1])
    if len(activities) > 2:
        G.add_edge(activities[0], activities[-1])
    info = {
        'package_name': app.package_name,
        'main_activity': app.main_activity,
        'activities': activities
    }
    return G, info


def multi_attribute_widget_matching(backtrack_info: Dict[str, Any], atg: nx.DiGraph) -> List[List[str]]:
    """
    Use page/layout names to match activities in the ATG, and generate rough paths
    from any node to the matched activity using shortest paths.
    """
    pages = {tb['page'] for tb in backtrack_info.get('tracebacks', [])}
    candidate_nodes = []
    for n in atg.nodes:
        lower = n.lower()
        if any(p.lower() in lower for p in pages):
            candidate_nodes.append(n)
    rough_paths: List[List[str]] = []
    nodes_list = list(atg.nodes)
    for dst in candidate_nodes:
        if not nodes_list:
            continue
        src = nodes_list[0]
        try:
            path = nx.shortest_path(atg, src, dst)
            rough_paths.append(path)
        except Exception:
            continue
    return rough_paths


def global_path_planning(llm: OpenAIAPI, package_name: str, activities: List[str], rough_paths: List[List[str]]):
    prompt = get_planning_prompt(package_name, activities, rough_paths)
    return llm.rank_potential_paths(prompt)


def run_pipeline(llm: OpenAIAPI, apk_path: str, android_repo_root: str, code_segment: Dict[str, Any] = None) -> Dict[str, Any]:
    if code_segment is None:
        code_segment = heuristic_detection_placeholder()

    widgets = gui_widget_association(code_segment, android_repo_root)
    back_info = interaction_path_backtracking(widgets)
    atg, app_info = build_atg_from_app(apk_path)
    rough_paths = multi_attribute_widget_matching(back_info, atg)
    potentials = global_path_planning(llm, app_info['package_name'], app_info['activities'], rough_paths)

    return {
        'code_segment': code_segment,
        'associated_widgets': widgets,
        'backtracking': back_info,
        'app_info': app_info,
        'rough_paths': rough_paths,
        'potential_paths': potentials
    }


