#pragma once
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <string_view>
#include <unordered_map>

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

	std::vector<uintptr_t>		allocation_list;
	std::vector<thread_data>	thread_list;
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

	[[nodiscard]] static std::optional<process>	from_pid(uintptr_t pid);
	[[nodiscard]] static std::optional<process>	from_name(std::wstring_view name);
	[[nodiscard]] static std::vector<process> get_process_list();
	
	[[nodiscard]] bool raw_read(uintptr_t address, size_t size, void* buffer) const;
	[[nodiscard]] bool raw_write(uintptr_t address, size_t size, const void* buffer) const;

	[[nodiscard]] std::optional<module_data> get_module(std::wstring name) const;
	[[nodiscard]] const std::wstring& get_executable_name() const;

	[[nodiscard]] uintptr_t get_process_id() const;
	[[nodiscard]] HANDLE get_process_handle() const;

	[[nodiscard]] uintptr_t find_pattern(const std::wstring& module_name, std::string_view pattern) const;

	[[nodiscard]] uint32_t adjust_protection(uintptr_t address, size_t size, uint32_t new_protection) const;
	uint32_t execute_code(uintptr_t address, uintptr_t argument, bool wait = false) const;

	[[nodiscard]] uintptr_t allocate(size_t size, uint32_t protection);
	void free(uintptr_t address);

	[[nodiscard]] const std::vector<thread_data>& get_thread_list() const;
	[[nodiscard]] const std::unordered_map<std::wstring, module_data>& get_module_list() const;

	template <typename T>
	[[nodiscard]] T read(const uintptr_t address) const
	{
		T buffer{};
		const auto result = raw_read(address, sizeof(T), &buffer);
		if (!result)
			throw std::runtime_error{"reading failed."};

		return buffer;
	}

	template <typename T>
	void write(const uintptr_t address, const T& buffer) const
	{
		const auto result = raw_write(address, sizeof(T), &buffer);
		if (!result)
			throw std::runtime_error{"writing failed."};
	}
};
