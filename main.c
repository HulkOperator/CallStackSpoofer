#include <Windows.h>

#include "spoofer.h"

int main() {

	HMODULE pUser32 = LoadLibraryA("User32");
	UINT64 pMessageBoxA = GetProcAddress(pUser32, "MessageBoxA");

	for (int i = 0; i < 5; i ++)
		CallStackSpoof(pMessageBoxA, 4, NULL, "Text", "Caption", MB_YESNO);


	printf("Clean Exit\n");
}
