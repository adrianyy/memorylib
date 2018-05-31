#pragma once
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <string_view>
#include <unordered_map>

//typedefs so we don't have to include any winapi headers here
using SYSTEM_PROCESS_INFORMATION = struct _SYSTEM_PROCESS_INFORMATION;
using HANDLE = void*;

struct thread_data
{
	const uintptr_t id;
	const HANDLE	handle;

	thread_data(const uintptr_t id, const HANDLE handle) :
		id(id), handle(handle)
	{
	}
};

struct module_data
{
	const uintptr_t base_address;
	const size_t	size;

	module_data(const uintptr_t base_address, const size_t size) :
		base_address(base_address), size(size)
	{
	}
};

class process
{
	HANDLE	  handle;
	uintptr_t pid;

	std::vector<uintptr_t> allocation_list;
	std::vector<thread_data> thread_list;
	std::unordered_map<std::wstring, module_data> module_list;
	
	process(HANDLE handle, uintptr_t pid, std::vector<thread_data> thread_list, std::unordered_map<std::wstring, module_data> module_list);

	static std::unique_ptr<SYSTEM_PROCESS_INFORMATION> get_system_process_information();
	static std::optional<process> from_process_information(SYSTEM_PROCESS_INFORMATION* process_information);

public:
	process() = delete;

	process(const process&) = delete;
	process& operator=(const process&) = delete;

	process(process&& process) noexcept;
	process& operator=(process&& process) noexcept;

	~process();

	static std::optional<process>	from_pid(uintptr_t pid);
	static std::optional<process>	from_name(std::wstring_view name);
	static std::vector<process>		get_process_list();
	
	bool raw_read(uintptr_t address, size_t size, void* buffer) const;
	bool raw_write(uintptr_t address, size_t size, const void* buffer) const;

	std::optional<module_data> get_module(const std::wstring& name) const;
	const std::wstring& get_executable_name() const;

	uintptr_t get_process_id() const;
	HANDLE get_process_handle() const;

	uintptr_t find_pattern(const std::wstring& module_name, std::string_view pattern) const;

	uint32_t adjust_protection(uintptr_t address, size_t size, uint32_t new_protection) const;
	uint32_t execute_code(uintptr_t address, uintptr_t argument, bool wait = false) const;

	uintptr_t allocate(size_t size, uint32_t protection);
	void free(uintptr_t address);

	const std::vector<thread_data>& get_thread_list() const;
	const std::unordered_map<std::wstring, module_data>& get_module_list() const;

	template <typename T>
	T read(const uintptr_t address) const
	{
		T buffer{};
		const auto result = raw_read(address, sizeof(T), &buffer);
		if (!result)
			throw std::exception("reading failed.");

		return buffer;
	}

	template <typename T>
	void write(const uintptr_t address, const T& buffer) const
	{
		const auto result = raw_write(address, sizeof(T), &buffer);
		if (!result)
			throw std::exception("writing failed.");
	}
};
