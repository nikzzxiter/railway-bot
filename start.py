from FIXEDENCODE_READYY import main
import nest_asyncio
import asyncio

if __name__ == "__main__":
    nest_asyncio.apply()
    asyncio.get_event_loop().run_until_complete(main())