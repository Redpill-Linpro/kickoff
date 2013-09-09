from lib import TestBase, FileCreator

from smmap.util import *

import os
import sys

class TestMMan(TestBase):
	
	def test_window(self):
		wl = MapWindow(0, 1)	 	# left
		wc = MapWindow(1, 1)		# center
		wc2 = MapWindow(10, 5)		# another center
		wr = MapWindow(8000, 50)	# right
		
		assert wl.ofs_end() == 1
		assert wc.ofs_end() == 2
		assert wr.ofs_end() == 8050
		
		# extension does nothing if already in place
		maxsize = 100
		wc.extend_left_to(wl, maxsize)
		assert wc.ofs == 1 and wc.size == 1
		wl.extend_right_to(wc, maxsize)
		wl.extend_right_to(wc, maxsize)
		assert wl.ofs == 0 and wl.size == 1
		
		# an actual left extension
		pofs_end = wc2.ofs_end()
		wc2.extend_left_to(wc, maxsize)
		assert wc2.ofs == wc.ofs_end() and pofs_end == wc2.ofs_end() 
		
		
		# respects maxsize
		wc.extend_right_to(wr, maxsize)
		assert wc.ofs == 1 and wc.size == maxsize
		wc.extend_right_to(wr, maxsize)
		assert wc.ofs == 1 and wc.size == maxsize
		
		# without maxsize
		wc.extend_right_to(wr, sys.maxint)
		assert wc.ofs_end() == wr.ofs and wc.ofs == 1
		
		# extend left
		wr.extend_left_to(wc2, maxsize)
		wr.extend_left_to(wc2, maxsize)
		assert wr.size == maxsize
		
		wr.extend_left_to(wc2, sys.maxint)
		assert wr.ofs == wc2.ofs_end()
		
		wc.align()
		assert wc.ofs == 0 and wc.size == align_to_mmap(wc.size, True)
		
	def test_region(self):
		fc = FileCreator(self.k_window_test_size, "window_test")
		half_size = fc.size / 2
		rofs = align_to_mmap(4200, False)
		rfull = MapRegion(fc.path, 0, fc.size)
		rhalfofs = MapRegion(fc.path, rofs, fc.size)
		rhalfsize = MapRegion(fc.path, 0, half_size)
		
		# offsets
		assert rfull.ofs_begin() == 0 and rfull.size() == fc.size
		assert rfull.ofs_end() == fc.size	# if this method works, it works always
		
		assert rhalfofs.ofs_begin() == rofs and rhalfofs.size() == fc.size - rofs
		assert rhalfsize.ofs_begin() == 0 and rhalfsize.size() == half_size
		
		assert rfull.includes_ofs(0) and rfull.includes_ofs(fc.size-1) and rfull.includes_ofs(half_size)
		assert not rfull.includes_ofs(-1) and not rfull.includes_ofs(sys.maxint)
		# with the values we have, this test only works on windows where an alignment 
		# size of 4096 is assumed.
		# We only test on linux as it is inconsitent between the python versions 
		# as they use different mapping techniques to circumvent the missing offset
		# argument of mmap.
		if sys.platform != 'win32':
			assert rhalfofs.includes_ofs(rofs) and not rhalfofs.includes_ofs(0)
		#END handle platforms
		
		# auto-refcount
		assert rfull.client_count() == 1
		rfull2 = rfull
		assert rfull.client_count() == 2
		
		# usage
		assert rfull.usage_count() == 0
		rfull.increment_usage_count()
		assert rfull.usage_count() == 1
		
		# window constructor
		w = MapWindow.from_region(rfull)
		assert w.ofs == rfull.ofs_begin() and w.ofs_end() == rfull.ofs_end()
		
	def test_region_list(self):
		fc = FileCreator(100, "sample_file")
		
		fd = os.open(fc.path, os.O_RDONLY)
		for item in (fc.path, fd):
			ml = MapRegionList(item)
			
			assert ml.client_count() == 1
			
			assert len(ml) == 0
			assert ml.path_or_fd() == item
			assert ml.file_size() == fc.size
		#END handle input
		os.close(fd)
		
	def test_util(self):
		assert isinstance(is_64_bit(), bool)	# just call it
		assert align_to_mmap(1, False) == 0
		assert align_to_mmap(1, True) == ALLOCATIONGRANULARITY
		
