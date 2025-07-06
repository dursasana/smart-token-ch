"""
NFT Contract Auditor — утилита для анализа NFT-контрактов на наличие уязвимостей и подозрительных паттернов.
"""

import requests
import argparse


ETHERSCAN_API = "https://api.etherscan.io/api"


def fetch_contract_source(address, api_key):
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key
    }
    response = requests.get(ETHERSCAN_API, params=params)
    data = response.json().get("result", [])
    return data[0] if data else None


def analyze_source_code(source_data):
    source = source_data.get("SourceCode", "")
    if not source:
        return ["Контракт закрыт или не верифицирован."]

    flags = []

    if "ownerOnly" not in source and "onlyOwner" not in source:
        flags.append("❗ Нет ограничений по владельцу — любой может выполнять чувствительные действия.")

    if "mint" in source.lower() and "public" in source.lower():
        flags.append("⚠️ Присутствует публичная функция mint — проверь лимиты/ограничения.")

    if "withdraw" in source.lower() and "msg.sender" not in source:
        flags.append("❗ Функция вывода средств без проверки владельца.")

    if "reentrancyGuard" not in source.lower():
        flags.append("⚠️ Нет защиты от атак повторного входа (Reentrancy).")

    if "selfdestruct" in source.lower():
        flags.append("❗ Контракт может быть уничтожен через selfdestruct.")

    return flags or ["✓ Опасных паттернов не обнаружено."]


def main():
    parser = argparse.ArgumentParser(description="Аудит NFT-смарт-контрактов на базе Ethereum.")
    parser.add_argument("address", help="Адрес контракта NFT")
    parser.add_argument("api_key", help="API ключ Etherscan")
    args = parser.parse_args()

    print(f"[•] Загружаем контракт {args.address} с Etherscan...")
    data = fetch_contract_source(args.address, args.api_key)

    if not data:
        print("Ошибка: не удалось получить исходный код.")
        return

    print("[✓] Контракт загружен. Анализ...")
    results = analyze_source_code(data)

    print("\nРезультаты аудита:")
    for item in results:
        print("-", item)


if __name__ == "__main__":
    main()
