# HexCore Debugger

Emulation-based debugger for PE/ELF binary analysis, part of the **HikariSystem HexCore**
binary analysis IDE. Drives the [Unicorn Engine](https://www.unicorn-engine.org/) (via
`hexcore-unicorn`) to single-step, set breakpoints, inspect registers/memory, and run
headless emulation traces.

## License

**GPL-2.0-only** - See [LICENSE](LICENSE) for details.

This component embeds `hexcore-unicorn`, which links the Unicorn Engine (GPL-2.0).
Because it links GPL code, the debugger extension is itself GPL-2.0-only. This does **not**
make the rest of the HexCore IDE GPL: the emulation worker runs out-of-process over IPC,
so the core IDE and the other `hexcore-*` extensions remain MIT. Only this extension and
`hexcore-unicorn` carry GPL-2.0.
