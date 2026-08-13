from typing import Optional
from openai import OpenAI, APIError, RateLimitError, BadRequestError, AuthenticationError, APIConnectionError


class OpenAIHandler:
    """Handler for interacting with OpenAI-compatible LLM endpoints for threat modeling."""

    DEFAULT_SYSTEM_PROMPT = (
        "You are an expert cybersecurity architect and threat modeling specialist. "
        "Your task is to analyze the provided architecture diagram description, identify security threats, "
        "categorize them according to the specified methodology (such as STRIDE, LINDDUN, CIA, etc.), "
        "and provide concrete, actionable preventive measures and mitigations."
    )

    def __init__(
        self,
        api_key: str,
        ai_model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        temperature: float = 0.2,
    ):
        kwargs = {"api_key": api_key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)
        self.model = ai_model
        self.temperature = temperature

    def do_threat_modeling(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Optional[str]:
        """Send the architecture prompt to the LLM and return the generated threat model."""
        context = system_prompt or self.DEFAULT_SYSTEM_PROMPT
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": context},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content
        except AuthenticationError as e:
            print(f"[ERROR] OpenAI Authentication failed. Please check your API key: {e}")
            return None
        except RateLimitError as e:
            print(f"[ERROR] OpenAI Rate limit exceeded: {e}")
            return None
        except BadRequestError as e:
            print(f"[ERROR] OpenAI Bad request error: {e}")
            return None
        except APIConnectionError as e:
            print(f"[ERROR] Failed to connect to OpenAI endpoint: {e}")
            return None
        except APIError as e:
            print(f"[ERROR] OpenAI API error: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Unexpected error during threat modeling generation: {e}")
            return None