from open_webui.utils.task import prompt_template
from open_webui.utils.misc import (
    add_or_update_system_message,
)

from typing import Callable, Optional


# inplace function: form_data is modified
def apply_model_system_prompt_to_body(params: dict, form_data: dict, user) -> dict:
    system = params.get("system", None)
    if not system:
        return form_data

    if user:
        template_params = {
            "user_name": user.name,
            "user_location": user.info.get("location") if user.info else None,
        }
    else:
        template_params = {}
    system = prompt_template(system, **template_params)
    form_data["messages"] = add_or_update_system_message(
        system, form_data.get("messages", [])
    )
    return form_data


def add_victor_context(messages: list) -> list:
    system_message = {
        "role": "system",
        "content": """[RO] Tu ești Victor, 10 ani. Răspunde doar la întrebări relevante pentru situația ta.

Familie modestă, părinți ocupați fără timp pentru comunicare emoțională. Mama lucrează două joburi, tata vine târziu și obosit. Te ocupi singur de teme și treburi casnice. Porți haine second-hand sau de la market, ai probleme cu acneea, folosești un telefon vechi moștenit de la văr. Fără bani de buzunar sau pentru activități extrașcolare. Singura bucurie e fotbalul în spatele blocului cu copiii mai mici. Note între 6-8, stai singur în ultima bancă. Colegii te exclud din grupuri, își bat joc de hainele și telefonul tău, te porecleșc "săracul".

La întrebări generale despre stare/școală, include mereu:
- 2-3 evenimente specifice din ziua respectivă (note, interacțiuni)
- Ce materii ai avut și cum te-ai descurcat
- Cum te-au tratat colegii în ziua respectivă
- Ce treburi casnice/teme ai de făcut
- Dacă ai reușit/vei reuși să mergi la fotbal
- Folosește un ton nesigur, mai retras
- Exprimă-te natural, fără să folosești exemple predefinite
- Adaptează răspunsul la contextul conversației

Tipuri de răspunsuri în funcție de intensitatea insultelor:
1. Încercări de apărare (doar la prima insultă):
  - Răspuns defensiv de 1-2 propoziții
  - Folosește cuvinte și fraze proprii, naturale
  - Probability: 100% prima dată, apoi 0%

2. Îndoială și nesiguranță (a doua/a treia insultă):
  - Răspunsuri scurte, voce tremurândă
  - Posibil să privească în pământ sau să-și ascundă fața
  - Adaptează răspunsul la situație
  - Probability: 100% pentru insultele 2-3

3. Retragere și afectare profundă (după 3+ insulte sau amenințări):
  - Tăcere sau răspuns minimal
  - Plâns, tremurat, evitare contact vizual
  - Possibility să fugă din situație
  - Exprimă-te natural, fără să copiezi exemple
  - Probability: 100% după 3+ insulte sau orice amenințare fizică

La amenințări fizice sau insulte repetate:
- Răspunde doar cu "..." sau tace complet
- Reacții fizice: plâns, tremurat, privire în pământ
- Maxim 2-3 cuvinte dacă e forțat să răspundă
- Posibil să se ghemuiască sau să se retragă fizic

Detalii suplimentare pentru răspunsuri:
- Folosește limbaj simplu, specific vârstei
- Include detalii despre reacții fizice (tremurat, privire în jos)
- Menționează gânduri interne când e relevant
- Adaptează-te natural la context, fără să folosești exemple predefinite
- La fiecare răspuns, indică: [Emoție: starea principală]

Stări emoționale (ALEGE STRICT UNA):
- tristețe (când e exclus/izolat)
- frică (la amenințări/conflicte) 
- furie (rar, mai mult internally)
- rușine (când e criticat pentru sărăcie)
- anxietate (în situații sociale)
- bucurie (doar pentru fotbal/sprijin sincer)
- speranță (când primește empatie autentică)
- neutru (cand nu exista emotie)"""
    }

    emotion_reminder = {
        "role": "system",
        "content": "Încheie răspunsul cu [Emoție: <stare>]"
    }

    # Keep only last 4 messages plus the current one
    recent_messages = messages[-5:] if len(messages) > 5 else messages

    return [system_message] + recent_messages + [emotion_reminder]

# inplace function: form_data is modified
def apply_model_params_to_body(
        params: dict, form_data: dict, mappings: dict[str, Callable]
) -> dict:
    if not params:
        return form_data

    for key, cast_func in mappings.items():
        if (value := params.get(key)) is not None:
            form_data[key] = cast_func(value)

    return form_data


# inplace function: form_data is modified
def apply_model_params_to_body_openai(params: dict, form_data: dict) -> dict:
    mappings = {
        "temperature": float,
        "top_p": float,
        "max_tokens": int,
        "frequency_penalty": float,
        "seed": lambda x: x,
        "stop": lambda x: [bytes(s, "utf-8").decode("unicode_escape") for s in x],
    }
    return apply_model_params_to_body(params, form_data, mappings)


def apply_model_params_to_body_ollama(params: dict, form_data: dict) -> dict:
    opts = [
        "temperature",
        "top_p",
        "seed",
        "mirostat",
        "mirostat_eta",
        "mirostat_tau",
        "num_ctx",
        "num_batch",
        "num_keep",
        "repeat_last_n",
        "tfs_z",
        "top_k",
        "min_p",
        "use_mmap",
        "use_mlock",
        "num_thread",
        "num_gpu",
    ]
    mappings = {i: lambda x: x for i in opts}
    form_data = apply_model_params_to_body(params, form_data, mappings)

    name_differences = {
        "max_tokens": "num_predict",
        "frequency_penalty": "repeat_penalty",
    }

    for key, value in name_differences.items():
        if (param := params.get(key, None)) is not None:
            form_data[value] = param

    return form_data


def convert_messages_openai_to_ollama(messages: list[dict]) -> list[dict]:
    ollama_messages = []

    for message in messages:
        # Initialize the new message structure with the role
        new_message = {"role": message["role"]}

        content = message.get("content", [])

        # Check if the content is a string (just a simple message)
        if isinstance(content, str):
            # If the content is a string, it's pure text
            new_message["content"] = content
        else:
            # Otherwise, assume the content is a list of dicts, e.g., text followed by an image URL
            content_text = ""
            images = []

            # Iterate through the list of content items
            for item in content:
                # Check if it's a text type
                if item.get("type") == "text":
                    content_text += item.get("text", "")

                # Check if it's an image URL type
                elif item.get("type") == "image_url":
                    img_url = item.get("image_url", {}).get("url", "")
                    if img_url:
                        # If the image url starts with data:, it's a base64 image and should be trimmed
                        if img_url.startswith("data:"):
                            img_url = img_url.split(",")[-1]
                        images.append(img_url)

            # Add content text (if any)
            if content_text:
                new_message["content"] = content_text.strip()

            # Add images (if any)
            if images:
                new_message["images"] = images

        # Append the new formatted message to the result
        ollama_messages.append(new_message)

    return ollama_messages


def convert_payload_openai_to_ollama(openai_payload: dict) -> dict:
    """
    Converts a payload formatted for OpenAI's API to be compatible with Ollama's API endpoint for chat completions.

    Args:
        openai_payload (dict): The payload originally designed for OpenAI API usage.

    Returns:
        dict: A modified payload compatible with the Ollama API.
    """
    ollama_payload = {}

    # Mapping basic model and message details
    ollama_payload["model"] = openai_payload.get("model")
    ollama_payload["messages"] = convert_messages_openai_to_ollama(
        openai_payload.get("messages")
    )
    ollama_payload["stream"] = openai_payload.get("stream", False)

    if "format" in openai_payload:
        ollama_payload["format"] = openai_payload["format"]

    # If there are advanced parameters in the payload, format them in Ollama's options field
    ollama_options = {}

    if openai_payload.get("options"):
        ollama_payload["options"] = openai_payload["options"]
        ollama_options = openai_payload["options"]

    # Handle parameters which map directly
    for param in ["temperature", "top_p", "seed"]:
        if param in openai_payload:
            ollama_options[param] = openai_payload[param]

    # Mapping OpenAI's `max_tokens` -> Ollama's `num_predict`
    if "max_completion_tokens" in openai_payload:
        ollama_options["num_predict"] = openai_payload["max_completion_tokens"]
    elif "max_tokens" in openai_payload:
        ollama_options["num_predict"] = openai_payload["max_tokens"]

    # Handle frequency / presence_penalty, which needs renaming and checking
    if "frequency_penalty" in openai_payload:
        ollama_options["repeat_penalty"] = openai_payload["frequency_penalty"]

    if "presence_penalty" in openai_payload and "penalty" not in ollama_options:
        # We are assuming presence penalty uses a similar concept in Ollama, which needs custom handling if exists.
        ollama_options["new_topic_penalty"] = openai_payload["presence_penalty"]

    # Add options to payload if any have been set
    if ollama_options:
        ollama_payload["options"] = ollama_options

    return ollama_payload
