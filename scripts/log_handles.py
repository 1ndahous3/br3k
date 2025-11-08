import br3k

if __name__ == "__main__":

    print("Script: Log process handles")
    print()

    br3k.init_sysapi()

    process = br3k.Process(current=True)
    process.log_handles()

    br3k.script_success()
