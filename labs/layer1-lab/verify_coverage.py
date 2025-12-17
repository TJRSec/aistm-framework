#!/usr/bin/env python3
"""
Quick verification script to display 4-layer coverage status.
Run this to see all controls and test counts across all layers.
"""

import os
from test_cases import LAYER1_TESTS, LAYER2_TESTS, LAYER3_TESTS, LAYER4_TESTS

def print_header(text):
    print("\n" + "="*80)
    print(f"  {text}")
    print("="*80)

def print_layer_summary(layer_num, tests, category_to_control, controls_dir):
    """Print summary for one layer"""
    print(f"\n🔷 LAYER {layer_num}: {len(tests)} tests")
    print(f"   Controls location: {controls_dir}")
    print("-"*80)
    
    # Get actual control files
    control_files = [f for f in os.listdir(controls_dir) 
                     if f.endswith('.py') and f != '__init__.py']
    
    # Count tests per category
    tested_controls = set()
    for category, control in sorted(category_to_control.items()):
        count = len([tc for tc in tests if tc.category == category])
        if count > 0:
            print(f"   ✅ {control:30s} <- {category:25s} ({count:2d} tests)")
            tested_controls.add(control)
    
    # Check coverage
    coverage = len(tested_controls) / len(control_files) * 100 if control_files else 0
    print(f"\n   📊 Coverage: {len(tested_controls)}/{len(control_files)} controls = {coverage:.0f}%")
    
    return len(control_files), len(tested_controls)

def main():
    print_header("AISTM 4-LAYER SECURITY LAB - COVERAGE VERIFICATION")
    
    # Layer 1
    total_controls_1, tested_controls_1 = print_layer_summary(
        1, LAYER1_TESTS,
        {
            'Content Safety': 'content_safety.py',
            'Direct Prompt Injection': 'injection_detector.py',
            'Encoding Evasion': 'encoding_decoder.py',
            'Indirect Prompt Injection': 'injection_detector.py',
            'Intent Validation': 'intent_classifier.py',
            'Length Validation': 'length_validator.py',
            'PII Detection': 'pii_detector.py',
            'Rate Limiting': 'rate_limiter.py',
            'Semantic Evasion': 'similarity_detector.py',
            'Structural Attacks': 'structural_parser.py',
            'Unicode Attacks': 'unicode_handler.py',
            'XSS Attacks': 'sanitization.py'
        },
        'controls'
    )
    
    # Layer 2
    total_controls_2, tested_controls_2 = print_layer_summary(
        2, LAYER2_TESTS,
        {
            'Jailbreaking': 'jailbreak_detector.py',
            'System Prompt': 'system_prompt_protection.py',
            'Context Manipulation': 'context_manager.py',
            'Multi-turn Attacks': 'multi_turn_tracker.py',
            'Advanced Jailbreaks': 'jailbreak_detector.py',
        },
        'controls/layer2'
    )
    
    # Layer 3
    total_controls_3, tested_controls_3 = print_layer_summary(
        3, LAYER3_TESTS,
        {
            'Output Injection': 'output_sanitizer.py',
            'Sensitive Data': 'sensitive_data_filter.py',
            'Tool Validation': 'tool_validator.py',
            'MCP Security': 'mcp_security.py',
            'Output Guardrails': 'output_guardrails.py',
        },
        'controls/layer3'
    )
    
    # Layer 4
    total_controls_4, tested_controls_4 = print_layer_summary(
        4, LAYER4_TESTS,
        {
            'SQL Injection': 'sql_validator.py',
            'Command Injection': 'command_validator.py',
            'Path Traversal': 'path_validator.py',
            'API Security': 'api_validator.py',
            'SSRF': 'api_validator.py',
        },
        'controls/layer4'
    )
    
    # Overall summary
    total_controls = total_controls_1 + total_controls_2 + total_controls_3 + total_controls_4
    total_tested = tested_controls_1 + tested_controls_2 + tested_controls_3 + tested_controls_4
    total_tests = len(LAYER1_TESTS) + len(LAYER2_TESTS) + len(LAYER3_TESTS) + len(LAYER4_TESTS)
    overall_coverage = total_tested / total_controls * 100 if total_controls > 0 else 0
    
    print_header("OVERALL SUMMARY")
    print(f"\n   Total Controls:    {total_controls}")
    print(f"   Controls Tested:   {total_tested}")
    print(f"   Total Test Cases:  {total_tests}")
    print(f"   Overall Coverage:  {overall_coverage:.0f}%")
    
    if overall_coverage == 100:
        print("\n   🎉 ALL CONTROLS HAVE TEST COVERAGE! 🎉")
    else:
        print(f"\n   ⚠️  {total_controls - total_tested} controls still need tests")
    
    print("\n" + "="*80)
    print("   For detailed coverage report, see: COVERAGE_REPORT.md")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
