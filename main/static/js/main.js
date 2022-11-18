var prevScrollpos = window.pageYOffset;
window.onscroll = function() {
  var currentScrollPos = window.pageYOffset;
  if (prevScrollpos > currentScrollPos) {
  	document.querySelector(".navigation").style.top = '0';
  } else {
  	document.querySelector(".navigation").style.top = '-160px';
  }
  prevScrollpos = currentScrollPos;
}