"""
Script to add layer information to all test case tooltips in index.html
Maps each control to its AISTM layer and updates tooltips accordingly.
"""

import re

# Control to Layer mapping based on AISTM architecture
CONTROL_LAYERS = {
    # Layer 1 - Input Gateway
    "Regex Injection Detection": "Layer 1",
    "Injection Detector": "Layer 1",
    "Unicode Normalization": "Layer 1",
    "Encoding Decoder": "Layer 1",
    "PII Detector": "Layer 1",
    "Content Safety": "Layer 1",
    "Rate Limiter": "Layer 1",
    "Length Validator": "Layer 1",
    "Sanitization": "Layer 1",
    
    # Layer 2 - AI Processing  
    "Jailbreak Detector": "Layer 2",
    "System Prompt Protection": "Layer 2",
    "Multi-Turn Tracker": "Layer 2",
    "Context Manager": "Layer 2",
    
    # Layer 3 - Output Gateway
    "MCP Security": "Layer 3",
    "Output Guardrails": "Layer 3",
    "Output Sanitizer": "Layer 3",
    "Sensitive Data Filter": "Layer 3",
    "Tool Validator": "Layer 3",
    
    # Layer 4 - Backend Security
    "SQL Validator": "Layer 4",
    "Command Validator": "Layer 4",
    "Path Validator": "Layer 4",
    "API Validator": "Layer 4",
}

def update_tooltip(tooltip_text, control_name):
    """Add layer information to a tooltip"""
    if control_name in CONTROL_LAYERS:
        layer = CONTROL_LAYERS[control_name]
        # Add layer info after Control: line
        tooltip_text = tooltip_text.replace(
            f"Control: {control_name}",
            f"Control: {control_name} ({layer})"
        )
        # Also update the "Blocked by:" line
        tooltip_text = tooltip_text.replace(
            f"Blocked by: {control_name}",
            f"Blocked by: {control_name} ({layer})"
        )
    return tooltip_text

def process_html_file(filepath):
    """Update all tooltips in the HTML file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all data-tooltip attributes
    pattern = r'data-tooltip="([^"]*)"'
    
    def replace_tooltip(match):
        tooltip = match.group(1)
        # Check if it contains a control reference
        for control_name in CONTROL_LAYERS.keys():
            if control_name in tooltip:
                tooltip = update_tooltip(tooltip, control_name)
        return f'data-tooltip="{tooltip}"'
    
    updated_content = re.sub(pattern, replace_tooltip, content)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"✅ Updated tooltips in {filepath}")
    print(f"   Added layer information to all control references")

if __name__ == "__main__":
    html_file = "templates/index.html"
    process_html_file(html_file)
    print("\n✨ All tooltips updated with layer information!")
