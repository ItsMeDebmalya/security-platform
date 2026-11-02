"""os_release: the distribution identity, as stated by /etc/os-release."""

from agent import modules
from agent.modules import Outcome
from agent.readfile import FileReader
from agent.run import Runner


def collect(runner: Runner, reader: FileReader) -> Outcome:
    res = reader.read_entry(modules.file_entry(reader, "os.release"))[0]
    problem = modules.file_problem(res)
    if problem:
        return problem
    v = res.values
    return modules.collected(
        {
            "id": v.get("ID"),
            "version_id": v.get("VERSION_ID"),
            "pretty_name": v.get("PRETTY_NAME"),
        }
    )
