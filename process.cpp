#include "process.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS

#include <Windows.h>

#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <winternl.h>
#include <algorithm>
#include <Psapi.h>
#include <cassert>
#include <cstdint>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace nt
{
	extern "C" BOOLEAN WINAPI RtlEqualUnicodeString(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);
	extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
	extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
}

namespace util
{
	__forceinline SYSTEM_PROCESS_INFORMATION* next(const SYSTEM_PROCESS_INFORMATION* current)
	{
		return reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(uintptr_t(current) + current->NextEntryOffset);
	}

	__forceinline bool is_valid(const HANDLE handle)
	{
		return handle && handle != INVALID_HANDLE_VALUE;
	}

	[[noreturn]] void throw_last_winapi_error()
	{
		char error_buffer[512];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			error_buffer, sizeof(error_buffer), nullptr);

		throw std::system_error{std::error_code{static_cast<int>(GetLastError()), std::system_category()}, error_buffer};
	}
}

constexpr uint32_t default_process_access = PROCESS_ALL_ACCESS;
constexpr uint32_t default_thread_access = THREAD_ALL_ACCESS;

process::process(const HANDLE handle, const uintptr_t pid, std::vector<thread_data> thread_list, std::unordered_map<std::wstring, module_data> module_list) :
	handle(handle), pid(pid), thread_list(std::move(thread_list)), module_list(std::move(module_list))
{
	assert(pid && util::is_valid(handle));
}

std::unique_ptr<SYSTEM_PROCESS_INFORMATION> process::get_system_process_information()
{
	using information_ptr = std::unique_ptr<SYSTEM_PROCESS_INFORMATION>;

	information_ptr information_buffer{};
	size_t			required_size{};

	auto status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, reinterpret_cast<PULONG>(&required_size));
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		information_buffer = information_ptr(reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(new uint8_t[required_size]));
		status = NtQuerySystemInformation(SystemProcessInformation, information_buffer.get(), required_size, reinterpret_cast<PULONG>(&required_size));
	}

	if (!NT_SUCCESS(status))
		throw std::system_error{std::error_code{static_cast<int>(status), std::system_category()}};

	return information_buffer;
}

std::optional<process> process::from_process_information(SYSTEM_PROCESS_INFORMATION* process_information)
{
	const auto pid	  = reinterpret_cast<uintptr_t>(process_information->UniqueProcessId);
	const auto handle = OpenProcess(default_process_access, false, pid);
	if (!util::is_valid(handle))
		return std::nullopt;

	HMODULE found_modules[2048]{};
	size_t	required_size{};

	if (!EnumProcessModulesEx(handle, found_modules, sizeof(found_modules), reinterpret_cast<LPDWORD>(&required_size), LIST_MODULES_ALL))
		return std::nullopt;

	std::unordered_map<std::wstring, module_data> modules;
	std::vector<thread_data> threads;

	for (size_t i{}; i < required_size / sizeof(HMODULE); ++i)
	{
		MODULEINFO info{};
		wchar_t base_name[MAX_PATH]{};

		const auto mod = found_modules[i];
		if (GetModuleInformation(handle, mod, &info, sizeof(MODULEINFO)) && GetModuleBaseNameW(handle, mod, base_name, MAX_PATH))
		{
			std::wstring module_name(base_name);
			std::transform(module_name.begin(), module_name.end(), module_name.begin(), towlower);

			modules.emplace(module_name, module_data(reinterpret_cast<uintptr_t>(info.lpBaseOfDll), info.SizeOfImage));
		}
	}

	for (size_t i{}; i < process_information->NumberOfThreads; ++i)
	{
		const auto& thread			= reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(process_information + 1)[i];
		const auto  thread_id		= reinterpret_cast<uintptr_t>(thread.ClientId.UniqueThread);
		const auto  thread_handle	= OpenThread(default_thread_access, false, thread_id); //it's ok if we can't get thread handle, no need to throw here

		threads.emplace_back(thread_id, thread_handle);
	}

	return std::make_optional(process(handle, pid, threads, modules));
}

process::process(const process& process)
{
	module_list		= process.module_list;
	pid				= process.pid;
	handle			= INVALID_HANDLE_VALUE;

	if (!DuplicateHandle(GetCurrentProcess(), process.handle, GetCurrentProcess(), &handle, 0, false, DUPLICATE_SAME_ACCESS))
		util::throw_last_winapi_error();

	for (const auto& thread : process.thread_list)
	{
		HANDLE new_handle = thread.handle;

		if (util::is_valid(thread.handle))
		{
			new_handle = INVALID_HANDLE_VALUE;

			if (!DuplicateHandle(GetCurrentProcess(), thread.handle, GetCurrentProcess(), &new_handle, 0, false, DUPLICATE_SAME_ACCESS))
				util::throw_last_winapi_error();
		}

		thread_list.emplace_back(thread.id, new_handle);
	}
}

process& process::operator=(process&& process) noexcept
{
	if (this == &process)
		return *this;

	allocation_list = std::move(process.allocation_list);
	module_list		= std::move(process.module_list);
	thread_list		= std::move(process.thread_list);
	pid				= process.pid;
	handle			= process.handle;

	process.handle	= INVALID_HANDLE_VALUE;
	process.pid		= 0;

	return *this;
}

process::process(process&& process) noexcept
{
	allocation_list = std::move(process.allocation_list);
	module_list		= std::move(process.module_list);
	thread_list		= std::move(process.thread_list);
	pid				= process.pid;
	handle			= process.handle;

	process.handle	= INVALID_HANDLE_VALUE;
	process.pid		= 0;
}

process::~process()
{
	if (util::is_valid(handle))
	{
		for (const auto address : allocation_list)
		{
			if (!VirtualFreeEx(handle, reinterpret_cast<void*>(address), 0, MEM_RELEASE))
				util::throw_last_winapi_error();
		}

		for (const auto thread : thread_list)
		{
			const auto thread_handle = thread.handle;
			if (util::is_valid(thread_handle))
			{
				if (!CloseHandle(thread_handle))
					util::throw_last_winapi_error();
			}
		}

		if (!CloseHandle(handle))
			util::throw_last_winapi_error();
	}
}

std::optional<process> process::from_pid(const uintptr_t pid)
{
	const auto wrapper = get_system_process_information();
	const auto process_information = wrapper.get();

	for (auto current = process_information; current->NextEntryOffset != 0; current = util::next(current))
	{
		if (reinterpret_cast<uintptr_t>(current->UniqueProcessId) == pid)
			return from_process_information(current);
	}

	return std::nullopt;
}

std::optional<process> process::from_name(const std::wstring_view name)
{
	const auto wrapper = get_system_process_information();
	const auto process_information = wrapper.get();

	UNICODE_STRING process_name{};
	RtlInitUnicodeString(&process_name, name.data());

	for (auto current = process_information; current->NextEntryOffset != 0; current = util::next(current))
	{
		if (nt::RtlEqualUnicodeString(&current->ImageName, &process_name, true))
		{
			auto result = from_process_information(current);
			if (result.has_value())
				return result;
		}
	}

	return std::nullopt;
}

std::vector<process> process::get_process_list()
{
	const auto wrapper = get_system_process_information();
	const auto process_information = wrapper.get();

	std::vector<process> process_list;

	for (auto current = process_information; current->NextEntryOffset != 0; current = util::next(current))
	{
		if (current->UniqueProcessId)
		{
			auto result = from_process_information(current);
			if (result.has_value())
				process_list.emplace_back(std::move(*result));
		}
	}

	return process_list;
}

bool process::raw_read(const uintptr_t address, const size_t size, void* buffer) const
{
	if (!util::is_valid(handle))
		throw std::runtime_error{"object has been moved."};

	size_t bytes_read{};
	const auto result = nt::NtReadVirtualMemory(handle, reinterpret_cast<void*>(address), buffer, size, reinterpret_cast<PULONG>(&bytes_read));

	return NT_SUCCESS(result) && bytes_read == size;
}

bool process::raw_write(const uintptr_t address, const size_t size, const void* buffer) const
{
	if (!util::is_valid(handle))
		throw std::runtime_error{"object has been moved."};

	size_t bytes_written{};
	const auto result = nt::NtWriteVirtualMemory(handle, reinterpret_cast<void*>(address), const_cast<void*>(buffer), size, reinterpret_cast<PULONG>(&bytes_written));

	return NT_SUCCESS(result) && bytes_written == size;
}

std::optional<module_data> process::get_module(std::wstring name) const
{
	std::transform(name.begin(), name.end(), name.begin(), towlower);

	const auto result = module_list.find(name);
	if (result == module_list.end())
		return std::nullopt;

	return std::make_optional(module_list.at(name));
}

uintptr_t process::find_pattern(const std::wstring& module_name, std::string_view pattern) const
{
	static const auto pattern_to_byte = [](const char* pattern)
	{
		auto bytes			= std::vector<int32_t>{};
		const auto start	= const_cast<char*>(pattern);
		const auto end		= const_cast<char*>(pattern) + std::strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;

				bytes.emplace_back(-1);
			}
			else
			{
				bytes.emplace_back(std::strtoul(current, &current, 16));
			}
		}

		return bytes;
	};

	const auto module_entry = get_module(module_name);
	if (!module_entry.has_value())
		throw std::runtime_error{"module does not exist."};

	const auto size			 = module_entry->size;
	const auto pattern_bytes = pattern_to_byte(pattern.data());

	const auto s = pattern_bytes.size();
	const auto d = pattern_bytes.data();

	for (size_t i{}; i < size - s; ++i)
	{
		bool found = true;
		for (size_t j{}; j < s; ++j)
		{
			if (read<uint8_t>(module_entry->base_address + i + j) != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
			return module_entry->base_address + i;
	}

	return 0;
}

uint32_t process::adjust_protection(const uintptr_t address, const size_t size, const uint32_t new_protection) const
{
	DWORD old_protection{};
	if (!VirtualProtectEx(handle, reinterpret_cast<void*>(address), size, new_protection, &old_protection))
		util::throw_last_winapi_error();

	return static_cast<uint32_t>(old_protection);
}

uint32_t process::execute_code(const uintptr_t address, const uintptr_t argument, const bool wait) const
{
	const auto thread = CreateRemoteThread(handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), reinterpret_cast<void*>(argument), 0, nullptr);
	if (!util::is_valid(thread))
		util::throw_last_winapi_error();

	if (wait)
	{
		DWORD exit_code{};

		if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED)
			util::throw_last_winapi_error();

		if (!GetExitCodeThread(thread, &exit_code))
			util::throw_last_winapi_error();

		if (!CloseHandle(thread))
			util::throw_last_winapi_error();

		return exit_code;
	}

	return 0;
}

uintptr_t process::allocate(const size_t size, const uint32_t protection)
{
	const auto memory = VirtualAllocEx(handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
	if (!memory)
		util::throw_last_winapi_error();

	const auto address = reinterpret_cast<uintptr_t>(memory);

	allocation_list.emplace_back(address);

	return address;
}

void process::free(const uintptr_t address)
{
	if (!VirtualFreeEx(handle, reinterpret_cast<void*>(address), 0, MEM_RELEASE))
		util::throw_last_winapi_error();

	const auto result = std::find(allocation_list.begin(), allocation_list.end(), address);
	if (result != allocation_list.end())
		allocation_list.erase(result);
}

const std::wstring& process::get_executable_name() const
{
	return module_list.begin()->first;
}

uintptr_t process::get_process_id() const
{
	return pid;
}

HANDLE process::get_process_handle() const
{
	return handle;
}

const std::vector<thread_data>& process::get_thread_list() const
{
	return thread_list;
}

const std::unordered_map<std::wstring, module_data>& process::get_module_list() const
{
	return module_list;
}
