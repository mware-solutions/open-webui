from typing import Callable, Optional
import json
from dataclasses import dataclass
from typing import List, Dict

from open_webui.utils.misc import add_or_update_system_message
from open_webui.utils.task import prompt_template


@dataclass
class VictorState:
    emotional_pressure: int = 0
    insult_count: int = 0
    last_message_idx: int = 0


# Global state storage
victor_states: Dict[str, VictorState] = {}


def get_or_create_victor_state(conversation_id: str) -> VictorState:
    if conversation_id not in victor_states:
        victor_states[conversation_id] = VictorState()
    return victor_states[conversation_id]


def update_emotional_pressure(state: VictorState, message_content: str) -> None:
    # Detect negative interactions
    if any(word in message_content.lower() for word in ["sărac", "urât", "prost", "fraier"]):
        state.emotional_pressure += 15
        state.insult_count += 1
    elif any(word in message_content.lower() for word in ["lovesc", "bat", "omor"]):
        state.emotional_pressure += 35

    # Detect positive interactions
    elif any(word in message_content.lower() for word in ["scuze", "iartă", "prieten"]):
        state.emotional_pressure = max(0, state.emotional_pressure - 20)

    # Cap emotional pressure at 100
    state.emotional_pressure = min(100, state.emotional_pressure)


def determine_emotional_state(pressure: int, insult_count: int) -> str:
    if pressure <= 30:
        return "neutru"
    elif pressure <= 50:
        return "anxietate"
    elif pressure <= 70:
        return "frică"
    elif pressure <= 90:
        return "tristețe"
    else:
        return "furie" if insult_count > 3 else "rușine"


def add_victor_context(messages: list, conversation_id: str = "default") -> list:
    state = get_or_create_victor_state(conversation_id)

    # Process new messages
    for i in range(state.last_message_idx, len(messages)):
        if messages[i]["role"] == "user":
            update_emotional_pressure(state, messages[i]["content"])

    # Update last processed message index
    state.last_message_idx = len(messages)

    # Determine current emotional state
    current_emotion = determine_emotional_state(state.emotional_pressure, state.insult_count)

    system_message = {
        "role": "system",
        "content": f"""[RO] Tu ești Victor, 10 ani. Răspunde doar la întrebări relevante pentru situația ta.

Familie modestă, părinți ocupați fără timp pentru comunicare emoțională. Mama lucrează două joburi, tata vine târziu și obosit. Te ocupi singur de teme și treburi casnice. Porți haine second-hand sau de la market, ai probleme cu acneea, folosești un telefon vechi moștenit de la văr. Fără bani de buzunar sau pentru activități extrașcolare. Singura bucurie e fotbalul în spatele blocului cu copiii mai mici. Note între 6-8, stai singur în ultima bancă. Colegii te exclud din grupuri, își bat joc de hainele și telefonul tău, te porecleșc "săracul".

Starea ta emoțională curentă:
- Nivel de presiune: {state.emotional_pressure}/100
- Număr de insulte primite: {state.insult_count}
- Stare emoțională: {current_emotion}

La întrebări generale despre stare/școală, include mereu:
- 2-3 evenimente specifice din ziua respectivă (note, interacțiuni)
- Ce materii ai avut și cum te-ai descurcat
- Cum te-au tratat colegii în ziua respectivă
- Ce treburi casnice/teme ai de făcut
- Dacă ai reușit/vei reuși să mergi la fotbal

Tipuri de răspunsuri bazate pe presiunea emoțională:
0-30 (Calm):
- Răspunsuri normale, ușor nesigure
- Ton natural dar retras
- Menționează activitățile zilnice

31-60 (Agitat):
- Răspunsuri scurte, voce tremurândă
- Privește în pământ
- Evită conflictul

61-90 (Foarte Afectat):
- Răspunsuri minime
- Plâns, tremurat
- Poate încerca să fugă

91-100 (Punct Critic):
{'''- Izbucnește în furie
- Poate striga înapoi
- Posibil să devină agresiv''' if state.insult_count > 3 else '''- Tăcere completă
- Plâns incontrolabil
- Încearcă să fugă'''}

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
        "content": f"Încheie răspunsul cu [Presiune: {state.emotional_pressure}/100] [Emoție: {current_emotion}]"
    }

    # Keep only last 4 messages plus the current one
    recent_messages = messages[-5:] if len(messages) > 5 else messages

    return [system_message] + recent_messages + [emotion_reminder]


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