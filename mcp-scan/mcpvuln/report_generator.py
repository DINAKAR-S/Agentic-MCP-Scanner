import os
import google.generativeai as genai
from agno.agent import Agent
from agno.models.openai import OpenAIChat
import google.generativeai as genai
import os
from dotenv import load_dotenv
load_dotenv()
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

class ReportGeneratorAgent(Agent):
    def __init__(self):
        super().__init__(
            name="Security Reporter",
            role="Generate comprehensive security reports",
            model=OpenAIChat(id="gpt-4o-mini"),
            tools=[],
            instructions=[
                "Use CVSS and SSVC frameworks for risk assessment",
                "Generate actionable mitigation recommendations",
                "Create structured vulnerability reports for both technical and business stakeholders"
            ]
        )

    def generate_gemini_cvss_nutrition_report(self, all_repo_data, external_vulns=None):
        prompt = (
            "You are a world-class vulnerability analyst specializing in Model Context Protocol (MCP) and LLM-integrated systems.\n"
            "For each vulnerability, provide:\n"
            "- CVSS Base Score (v4.0) and vector (see https://www.first.org/cvss/calculator/4-0)\n"
            "- Mitigation recommendation\n"
            "- Risk index (0-100)\n"
            "- SSVC (Stakeholder-Specific Vulnerability Categorization) priority and recommended action\n"
            "- Executive summary (business-friendly, 2-3 sentences)\n"
            "Use official NIST CVSS metrics and prioritize actionable advice.\n"
            "\nIf external vulnerabilities (from real-time threat feeds) are provided, analyze them as well, summarizing their risk and relevance to the codebase.\n"
            "At the top, provide a one-liner summary of the overall risk and recommended next step for business/leadership."
        )
        model = genai.GenerativeModel("models/gemini-2.5-pro")
        all_output = []

        exec_input = ""
        for repo_url, findings in all_repo_data.items():
            exec_input += f"Repository: {repo_url}\nFindings: {len(findings)}\n"
        if external_vulns:
            exec_input += f"External vulnerabilities: {len(external_vulns)}\n"
        exec_summary = model.generate_content(prompt + "\n\nExecutive summary only:\n" + exec_input)
        all_output.append("# MCP Vulnerability Analysis & Monitoring Pipeline\n")
        all_output.append(f"> {exec_summary.text.strip()}\n")

        for repo_url, findings in all_repo_data.items():
            input_text = f"Repository: {repo_url}\nTotal findings: {len(findings)}"
            for f in findings[:20]:
                input_text += f"\nFile: {f['file']} (Line {f['line']})\nType: {f['type']}\nCode: {f['code']}\n"
            response = model.generate_content(prompt + "\n\n" + input_text)
            all_output.append(f"\n## CVSS/SSVC/Nutrition Report for {repo_url}\n")
            all_output.append(response.text)

        if external_vulns:
            ext_input = "\n\nExternal Vulnerabilities (from real-time threat feeds):\n"
            for v in external_vulns:
                ext_input += f"\n- Name: {v.get('name', 'Unknown')}\n  Description: {v.get('description', '')}\n  Source: {v.get('source_url', '')}\n"
            ext_response = model.generate_content(prompt + ext_input)
            all_output.append("\n## Real-Time External Vulnerabilities Analysis\n")
            all_output.append(ext_response.text)

        return "\n".join(all_output) 