## Amazon S3 manager
## Author: Michal Ludvig <michal@logix.cz>
##         http://www.logix.cz/michal
## License: GPL Version 2

import sys
import datetime
from Utils import formatSize

class Progress(object):
	def __init__(self, label, total_size):
		self.new_file(label, total_size)
	
	def new_file(self, label, total_size):
		self.label = label
		self.total_size = total_size
		# Set initial_position to something in the
		# case we're not counting from 0. For instance
		# when appending to a partially downloaded file.
		# Setting initial_position will let the speed
		# be computed right.
		self.initial_position = 0
		self.current_position = self.initial_position
		self.time_start = datetime.datetime.now()
		self.time_last = self.time_start
		self.time_current = self.time_start

		self.display(new_file = True)
	
	def update(self, current_position = -1, delta_position = -1):
		self.time_last = self.time_current
		self.time_current = datetime.datetime.now()
		if current_position > -1:
			self.current_position = current_position
		elif delta_position > -1:
			self.current_position += delta_position
		#else:
		#	no update, just call display()
		self.display()

	def done(self, message):
		self.display(done_message = message)

	def display(self, new_file = False, done_message = None):
		"""
		display(new_file = False[/True], done = False[/True])

		Override this method to provide a nicer output.
		"""
		if new_file:
			sys.stdout.write("%s  " % self.label[:30].ljust(30))
			sys.stdout.flush()
			self.last_milestone = 0
			return

		if self.current_position == self.total_size:
			print_size = formatSize(self.current_position, True)
			if print_size[1] != "": print_size[1] += "B"
			timedelta = self.time_current - self.time_start
			sec_elapsed = timedelta.days * 86400 + timedelta.seconds + float(timedelta.microseconds)/1000000.0
			print_speed = formatSize((self.current_position - self.initial_position) / sec_elapsed, True, True)
			sys.stdout.write("100%%  %s%s in %.2fs (%.2f %sB/s)\n" % 
				(print_size[0], print_size[1], sec_elapsed, print_speed[0], print_speed[1]))
			sys.stdout.flush()
			return

		rel_position = selfself.current_position * 100 / self.total_size
		if rel_position >= self.last_milestone:
			self.last_milestone = (int(rel_position) / 5) * 5
			sys.stdout.write("%d%% ", self.last_milestone)
			sys.stdout.flush()
			return

class ProgressANSI(Progress):
    ## http://en.wikipedia.org/wiki/ANSI_escape_code
	SCI = '\x1b['
	ANSI_hide_cursor = SCI + "?25l"
	ANSI_show_cursor = SCI + "?25h"
	ANSI_save_cursor_pos = SCI + "s"
	ANSI_restore_cursor_pos = SCI + "u"
	ANSI_move_cursor_to_column = SCI + "%uG"
	ANSI_erase_to_eol = SCI + "0K"

	def display(self, new_file = False, done_message = None):
		"""
		display(new_file = False[/True], done_message = None)
		"""
		if new_file:
			sys.stdout.write("%s  " % self.label[:30].ljust(30))
			#sys.stdout.write(self.ANSI_hide_cursor)
			sys.stdout.write(self.ANSI_save_cursor_pos)
			sys.stdout.flush()
			return

		timedelta = self.time_current - self.time_start
		sec_elapsed = timedelta.days * 86400 + timedelta.seconds + float(timedelta.microseconds)/1000000.0
		if (sec_elapsed > 0):
			print_speed = formatSize((self.current_position - self.initial_position) / sec_elapsed, True, True)
		else:
			print_speed = (0, "")
		sys.stdout.write(self.ANSI_restore_cursor_pos)
		sys.stdout.write(self.ANSI_erase_to_eol)
		sys.stdout.write("%(current)s of %(total)s   %(percent)3d%% in %(elapsed)ds  %(speed).2f %(speed_coeff)sB/s" % {
			"current" : str(self.current_position).rjust(len(str(self.total_size))),
			"total" : self.total_size,
			"percent" : self.total_size and (self.current_position * 100 / self.total_size) or 0,
			"elapsed" : sec_elapsed,
			"speed" : print_speed[0],
			"speed_coeff" : print_speed[1]
		})

		if done_message:
			sys.stdout.write("  %s\n" % done_message)

		sys.stdout.flush()
