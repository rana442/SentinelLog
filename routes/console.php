<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('syslog:maintenance')->everyFifteenMinutes()->withoutOverlapping();
